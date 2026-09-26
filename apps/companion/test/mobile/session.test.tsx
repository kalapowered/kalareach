/**
 * The phone's session view shows only what it read for the session on screen.
 *
 * Every read's answer is kept with the session it was read for and shown only for that session,
 * from the first render after a change of session, and a read made for a session the view has left
 * is never shown. Before its first answer the conversation says it is reading, and a refused read
 * says so rather than calling the conversation empty.
 */

import { Profiler, type ReactNode } from 'react'
import { describe, expect, it, vi } from 'vitest'
import { act, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import type { DocumentNode } from '@kalareach/plugin-sdk'

import { AppProvider } from '../../src/app/state'
import { fakeHost, terminalScreen, type HeldReads } from '../../src/host/fake'
import { describeMode } from '../../src/mobile/model/gestures'
import { MobileSession } from '../../src/mobile/views/MobileSession'
import { useLifecycle } from '../../src/mobile/useLifecycle'
import { SLOW_MS, WAITING } from '../../src/terminal/modes'

const SESSION_MAIN = '8a7b6c50-22bb-4c3d-8e4f-000000000101'
const SESSION_BUILD = '8a7b6c50-22bb-4c3d-8e4f-000000000102'

/** The session view on its own, for one session, as the phone's shell renders it. */
function OnSession({ sessionId }: { readonly sessionId: string }): ReactNode {
  const lifecycle = useLifecycle(null)
  return <MobileSession sessionId={sessionId} surface="ios" lifecycle={lifecycle} connected={true} />
}

/** Answers the held read at `index`, and lets everything that answer sets off run. */
async function answer(held: HeldReads, index: number): Promise<void> {
  await act(async () => {
    held.answer(index)
    await new Promise((resolve) => {
      setTimeout(resolve, 0)
    })
  })
}

async function made(held: HeldReads, count: number): Promise<void> {
  await waitFor(() => {
    expect(held.count).toBe(count)
  })
}

function message(id: string, text: string): DocumentNode {
  return { id, revision: '1', body: { kind: 'message', author: 'agent', text } }
}

describe("the phone's session view keeps each read to its own session", () => {
  it('shows nothing of the session it has left, from the first render after the change', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    controls.presentTerminal('viewport', 'size_mismatch')
    // What the page shows at each commit, read as each commit is made.
    const commits: string[] = []
    const onSession = (sessionId: string) => (
      <AppProvider port={port}>
        <Profiler
          id="session"
          onRender={() => {
            commits.push(document.body.textContent ?? '')
          }}
        >
          <OnSession sessionId={sessionId} />
        </Profiler>
      </AppProvider>
    )
    const { rerender } = render(onSession(SESSION_MAIN))
    await person.click(screen.getByRole('tab', { name: 'Terminal' }))
    expect((await screen.findByTestId('terminal-presentation')).textContent).toContain(
      "its size is not the session's"
    )
    await waitFor(() => {
      expect(screen.getByTestId('mobile-terminal').textContent).toContain('cargo test')
    })

    // Session 2's view publishes nothing, so nothing of it is shown either.
    controls.holdTerminalViews()
    commits.length = 0
    rerender(onSession(SESSION_BUILD))

    expect(commits.length).toBeGreaterThan(0)
    for (const text of commits) {
      expect(text).not.toContain("its size is not the session's")
      expect(text).not.toContain('cargo test')
    }
  })

  it('shows no conversation read for a session it has left', async () => {
    const { port, controls } = fakeHost()
    const held = controls.hold('agentSnapshot')
    const onSession = (sessionId: string) => (
      <AppProvider port={port}>
        <OnSession sessionId={sessionId} />
      </AppProvider>
    )
    const { rerender } = render(onSession(SESSION_MAIN))
    await made(held, 1)

    // The host moves on, and the view changes session before the first read answers.
    act(() => {
      controls.appendNode(message('n-7', 'Written after the first read.'))
    })
    rerender(onSession(SESSION_BUILD))
    await made(held, 2)

    await answer(held, 1)
    expect(screen.getByText('Written after the first read.')).toBeInTheDocument()
    await answer(held, 0)
    expect(screen.getByText('Written after the first read.')).toBeInTheDocument()
  })

  it('says it is reading the conversation before the first answer, not that it is empty', async () => {
    const { port, controls } = fakeHost()
    const held = controls.hold('agentSnapshot')
    render(
      <AppProvider port={port}>
        <OnSession sessionId={SESSION_MAIN} />
      </AppProvider>
    )
    await made(held, 1)

    expect(screen.getByText('Reading the conversation…')).toBeInTheDocument()
    expect(screen.queryByText('Nothing in this conversation yet.')).toBeNull()
    await answer(held, 0)
    expect(screen.getByText('Find why the reconnect test is flaky.')).toBeInTheDocument()
    expect(screen.queryByText('Reading the conversation…')).toBeNull()
  })

  it('shows a refused read as a refusal, in the host’s words, not as an empty conversation', async () => {
    const { port, controls } = fakeHost()
    controls.setConnected(false)
    render(
      <AppProvider port={port}>
        <OnSession sessionId={SESSION_MAIN} />
      </AppProvider>
    )

    expect(await screen.findByText('This conversation could not be read')).toBeInTheDocument()
    expect(screen.getByText('This host cannot be contacted right now.')).toBeInTheDocument()
    expect(screen.queryByText('Nothing in this conversation yet.')).toBeNull()
  })

  it('shows a refusal that came with no words as a refusal, not as an empty conversation', async () => {
    const { port } = fakeHost()
    render(
      <AppProvider
        port={{
          ...port,
          agentSnapshot: () =>
            Promise.reject({ code: 'RESOURCE_UNAVAILABLE', message: '', user_action: 'retry' })
        }}
      >
        <OnSession sessionId={SESSION_MAIN} />
      </AppProvider>
    )

    expect(await screen.findByText('This conversation could not be read')).toBeInTheDocument()
    expect(screen.getByText('Something went wrong.')).toBeInTheDocument()
    expect(screen.queryByText('Nothing in this conversation yet.')).toBeNull()
  })

  it('shows the conversation it read when nothing changed in between', async () => {
    const { port } = fakeHost()
    render(
      <AppProvider port={port}>
        <OnSession sessionId={SESSION_MAIN} />
      </AppProvider>
    )
    expect(await screen.findByText('Find why the reconnect test is flaky.')).toBeInTheDocument()
  })
})

describe("the phone's raw terminal view (KR-REQ-08.02, 13.18)", () => {
  async function onTerminal(port: Parameters<typeof AppProvider>[0]['port']) {
    const person = userEvent.setup()
    render(
      <AppProvider port={port}>
        <OnSession sessionId={SESSION_MAIN} />
      </AppProvider>
    )
    await person.click(screen.getByRole('tab', { name: 'Terminal' }))
    return person
  }

  it('draws the screen as text, each piece at its column, in the same words as the desktop', async () => {
    const { port } = fakeHost()
    await onTerminal(port)
    await waitFor(() => {
      expect(screen.getAllByTestId('mobile-terminal-line')).toHaveLength(8)
    })
    const lines = screen.getAllByTestId('mobile-terminal-line').map((line) => line.textContent)
    expect(lines[0]).toBe('$ cargo test -p kr-client\n')
    expect(lines[3]).toBe('ok    done\n')
    // Each piece is a box of exactly its cells that cuts what it holds at its edges, so no glyph,
    // an italic one's overhang included, reaches the cells beside it.
    const pieces = Array.from(
      screen.getAllByTestId('mobile-terminal-line')[3]?.querySelectorAll<HTMLElement>('[data-cells]') ?? []
    )
    expect(pieces.map((piece) => [piece.textContent, piece.style.width])).toEqual([
      ['ok', '2ch'],
      ['  ', '2ch'],
      ['done', '4ch']
    ])
    for (const piece of pieces) {
      expect(piece.style.display).toBe('inline-block')
      expect(piece.style.overflow).toBe('hidden')
    }
    expect(screen.getByTestId('terminal-presentation').textContent).toContain(
      'its client declared no terminal profile'
    )
    expect(screen.getByTestId('mobile-terminal')).toHaveAttribute('aria-busy', 'false')
  })

  it("colours a selection in the session's selection colours, and a new palette's replace them", async () => {
    const { port, controls } = fakeHost()
    await onTerminal(port)
    await waitFor(() => {
      expect(screen.getAllByTestId('mobile-terminal-line')).toHaveLength(8)
    })
    const grid = screen.getByTestId('mobile-terminal').querySelector<HTMLElement>('.m-terminal-grid')
    const name = grid?.getAttribute('data-terminal-grid') ?? ''
    expect(name).not.toBe('')
    /** Every selection rule the grid carries. */
    const rules = () =>
      Array.from(grid?.querySelectorAll('style[data-terminal-selection]') ?? []).map((rule) => rule.textContent)
    // One rule, for this grid alone, in the palette's selection colours.
    expect(rules()).toHaveLength(1)
    expect(rules()[0]).toContain(`[data-terminal-grid="${name}"] ::selection`)
    expect(rules()[0]).toContain('background-color: #315e4a')
    expect(rules()[0]).toContain('color: #ffffff')

    const palette = terminalScreen(SESSION_MAIN, { columns: 80, rows: 8 }).palette
    act(() => {
      controls.terminalViews[0]?.show({
        palette: {
          ...palette,
          selection_background: { red: 0x12, green: 0x34, blue: 0x56 },
          selection_foreground: { red: 0xfe, green: 0xdc, blue: 0xba }
        }
      })
    })
    expect(rules()).toHaveLength(1)
    expect(rules()[0]).toContain('background-color: #123456')
    expect(rules()[0]).toContain('color: #fedcba')
    expect(rules()[0]).not.toContain('#315e4a')
  })

  it('says it is attaching before its view has attached, and draws nothing', async () => {
    const { port, controls } = fakeHost()
    controls.holdTerminalViews()
    await onTerminal(port)
    await waitFor(() => {
      expect(controls.terminalViews).toHaveLength(1)
    })
    expect(screen.getByTestId('terminal-presentation').textContent).toBe(
      'Attaching to this session…'
    )
    expect(screen.queryAllByTestId('mobile-terminal-line')).toEqual([])
    expect(screen.getByTestId('mobile-terminal')).toHaveAttribute('aria-busy', 'true')
  })

  it('closes its view when the person goes back to the conversation', async () => {
    const { port, controls } = fakeHost()
    const person = await onTerminal(port)
    await waitFor(() => {
      expect(controls.terminalViews).toHaveLength(1)
    })
    await person.click(screen.getByRole('tab', { name: 'Conversation' }))
    await waitFor(() => {
      expect(controls.terminalViews[0]?.closed).toBe(true)
    })
  })

  it('warns of cells left blank, rows cut short and a shortened screen, in the desktop words', async () => {
    const { port, controls } = fakeHost()
    await onTerminal(port)
    await waitFor(() => {
      expect(screen.getAllByTestId('mobile-terminal-line')).toHaveLength(8)
    })
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

    // A piece the phone draws as blank cells is counted with the ones native code left blank.
    const first = whole.lines[0]?.pieces[0]
    if (first === undefined) throw new Error('the scripted screen has a piece')
    act(() => {
      controls.terminalViews[0]?.show({
        ...whole,
        replaced: 3,
        lines: whole.lines.map((line, index) =>
          index === 6 ? { ...line, pieces: [{ ...first, column: 0, cells: 2, text: '\u{4e2d}' }] } : line
        )
      })
    })
    expect(screen.getByTestId('substituted-count').textContent).toBe('4 left blank')
  })

  it('keeps the last frame while it waits, busy at once and saying so only after a moment', async () => {
    const { port, controls } = fakeHost()
    await onTerminal(port)
    await waitFor(() => {
      expect(screen.getAllByTestId('mobile-terminal-line')).toHaveLength(8)
    })
    act(() => {
      controls.terminalViews[0]?.wait()
    })
    expect(screen.getByTestId('mobile-terminal')).toHaveAttribute('aria-busy', 'true')
    expect(screen.queryByTestId('terminal-position')?.textContent ?? '').not.toBe(WAITING)
    await waitFor(
      () => {
        expect(screen.getByTestId('terminal-position').textContent).toBe(WAITING)
      },
      { timeout: SLOW_MS * 20 }
    )
    expect(screen.getAllByTestId('mobile-terminal-line')[0]?.textContent).toBe(
      '$ cargo test -p kr-client\n'
    )
    act(() => {
      controls.terminalViews[0]?.show()
    })
    expect(screen.queryByTestId('terminal-position')).toBeNull()
    expect(screen.getByTestId('mobile-terminal')).toHaveAttribute('aria-busy', 'false')
  })

  it('opens again when the host connection comes back after an open was refused', async () => {
    const { port, controls } = fakeHost()
    controls.setConnected(false)
    await onTerminal(port)
    expect(await screen.findByText(/This session could not be reached/)).toBeInTheDocument()
    act(() => {
      controls.setConnected(true)
    })
    await waitFor(() => {
      expect(controls.terminalViews).toHaveLength(2)
    })
    await waitFor(() => {
      expect(screen.getAllByTestId('mobile-terminal-line')).toHaveLength(8)
    })
    expect(screen.queryByText(/This session could not be reached/)).toBeNull()
  })

  it('reports the grid a pinch leaves it with', async () => {
    // jsdom lays nothing out, so the few measurements the view takes are given here: a surface
    // 336 pixels wide and 420 high, 8 pixels of padding around the grid, and cells of 8 by 16
    // pixels at the unscaled size, which grow with the zoom as the font does. The pane around the
    // surface measures nothing: the grid is what the surface shows.
    const ownStyle = window.getComputedStyle.bind(window)
    const zoomOf = (element: Element) =>
      Number(
        element.closest<HTMLElement>('[data-testid="mobile-terminal"]')?.style.getPropertyValue('--zoom') ||
          1
      )
    // Every other element measures nothing, as jsdom's own answer is.
    const rects = vi.spyOn(Element.prototype, 'getBoundingClientRect').mockImplementation(function (
      this: Element
    ) {
      const text = this.textContent ?? ''
      if (this.getAttribute('aria-hidden') !== 'true' || !/^M+$/.test(text)) return new DOMRect()
      const zoom = zoomOf(this)
      return DOMRect.fromRect({ x: 0, y: 0, width: text.length * 8 * zoom, height: 16 * zoom })
    })
    const widths = vi.spyOn(Element.prototype, 'clientWidth', 'get').mockImplementation(function (
      this: Element
    ) {
      return this.getAttribute('data-testid') === 'mobile-terminal' ? 336 : 0
    })
    const heights = vi.spyOn(Element.prototype, 'clientHeight', 'get').mockImplementation(function (
      this: Element
    ) {
      return this.getAttribute('data-testid') === 'mobile-terminal' ? 420 : 0
    })
    const styles = vi.spyOn(window, 'getComputedStyle').mockImplementation((element, pseudo) =>
      element.classList.contains('m-terminal-grid')
        ? ({
            paddingLeft: '8px',
            paddingRight: '8px',
            paddingTop: '8px',
            paddingBottom: '8px'
          } as CSSStyleDeclaration)
        : ownStyle(element, pseudo)
    )
    try {
      const { port, controls } = fakeHost()
      await onTerminal(port)
      await waitFor(() => {
        expect(screen.getAllByTestId('mobile-terminal-line').length).toBeGreaterThan(0)
      })
      // 320 pixels across and 404 down, in cells of 8 by 16.
      expect(controls.terminalViews[0]?.grids.at(-1)).toEqual({ columns: 40, rows: 25 })

      const surface = screen.getByTestId('mobile-terminal')
      const finger = (type: string, pointerId: number, clientX: number) => {
        act(() => {
          surface.dispatchEvent(
            new PointerEvent(type, { bubbles: true, pointerId, pointerType: 'touch', clientX, clientY: 100 })
          )
        })
      }
      // Two fingers 100 pixels apart move to 160: a pinch outwards, one step larger.
      finger('pointerdown', 1, 100)
      finger('pointerdown', 2, 200)
      finger('pointermove', 2, 260)
      finger('pointerup', 2, 260)
      finger('pointerup', 1, 100)
      expect(await screen.findByText('Zoom 113%')).toBeInTheDocument()
      // Cells of 9 by 18 now: 35 across and 22 down.
      await waitFor(() => {
        expect(controls.terminalViews[0]?.grids.at(-1)).toEqual({ columns: 35, rows: 22 })
      })
      expect(controls.terminalViews).toHaveLength(1)
    } finally {
      rects.mockRestore()
      widths.mockRestore()
      heights.mockRestore()
      styles.mockRestore()
    }
  })

  /**
   * Gives the phone's view the measurements jsdom does not take: cells of `cell`, 8 by 16 pixels
   * unless told, read at each measure, and a surface 336 pixels wide and 420 high. Returns what
   * puts them back.
   */
  function measured(cell: { width: number; height: number } = { width: 8, height: 16 }): () => void {
    const rects = vi.spyOn(Element.prototype, 'getBoundingClientRect').mockImplementation(function (
      this: Element
    ) {
      const text = this.textContent ?? ''
      if (this.getAttribute('aria-hidden') !== 'true' || !/^M+$/.test(text)) return new DOMRect()
      return DOMRect.fromRect({ x: 0, y: 0, width: text.length * cell.width, height: cell.height })
    })
    const widths = vi.spyOn(Element.prototype, 'clientWidth', 'get').mockImplementation(function (
      this: Element
    ) {
      return this.getAttribute('data-testid') === 'mobile-terminal' ? 336 : 0
    })
    const heights = vi.spyOn(Element.prototype, 'clientHeight', 'get').mockImplementation(function (
      this: Element
    ) {
      return this.getAttribute('data-testid') === 'mobile-terminal' ? 420 : 0
    })
    return () => {
      rects.mockRestore()
      widths.mockRestore()
      heights.mockRestore()
    }
  }

  /** One finger's `type` at `x`, `y`, or a mouse's when told. */
  function fingerEvent(type: string, pointerId: number, x: number, y: number, pointerType = 'touch'): PointerEvent {
    return new PointerEvent(type, { bubbles: true, cancelable: true, pointerId, pointerType, clientX: x, clientY: y })
  }

  /** One finger's `type` on the phone's terminal at `x`, `y`. */
  function finger(type: string, pointerId: number, x: number, y: number): void {
    act(() => {
      screen.getByTestId('mobile-terminal').dispatchEvent(fingerEvent(type, pointerId, x, y))
    })
  }

  /** How far `element` is drawn from its place, in pixels. */
  function translation(element: HTMLElement | null | undefined): { x: number; y: number } {
    const found = /translate\((-?[\d.]+)px, (-?[\d.]+)px\)/.exec(element?.style.transform ?? '')
    return found === null ? { x: 0, y: 0 } : { x: Number(found[1]), y: Number(found[2]) }
  }

  /** How far the phone's grid is drawn from its place, in pixels: the moves waiting and the drag's part. */
  function gridShift(): { x: number; y: number } {
    const grid = screen.getByTestId('mobile-terminal').querySelector<HTMLElement>('.m-terminal-grid')
    const waiting = translation(grid)
    const dragged = translation(grid?.parentElement)
    const x = waiting.x + dragged.x
    const y = waiting.y + dragged.y
    return { x: x === 0 ? 0 : x, y: y === 0 ? 0 : y }
  }

  it('moves the window with a one-finger drag in view mode, and taking control brings it back', async () => {
    const restore = measured()
    try {
      const { port, controls } = fakeHost()
      controls.holdTerminalMoves()
      const person = await onTerminal(port)
      await waitFor(() => {
        expect(screen.getAllByTestId('mobile-terminal-line').length).toBeGreaterThan(0)
      })
      await person.click(screen.getByRole('button', { name: 'Look around' }))
      expect(
        screen.getByText('View: drag to move around the session, pinch to make the text larger or smaller.')
      ).toBeInTheDocument()
      // Down a row and a half: the window goes up a row, and the screen follows the finger.
      finger('pointerdown', 1, 100, 100)
      finger('pointermove', 1, 100, 124)
      expect(controls.terminalViews[0]?.moves).toEqual([{ number: 1, across: 0, down: -1 }])
      expect(gridShift()).toEqual({ x: 0, y: 24 })
      // Lifted there: the half rounds to one more row, and the screen rests on whole rows.
      finger('pointerup', 1, 100, 124)
      expect(controls.terminalViews[0]?.moves).toEqual([
        { number: 1, across: 0, down: -1 },
        { number: 2, across: 0, down: -1 }
      ])
      expect(gridShift()).toEqual({ x: 0, y: 32 })
      expect(screen.getByTestId('mobile-terminal')).toHaveAttribute('aria-busy', 'true')
      // Taking control brings the window back to the live screen, behind the moves made.
      await person.click(screen.getByRole('button', { name: 'Take control' }))
      expect(controls.terminalViews[0]?.moves.at(-1)).toEqual({ number: 3, live: true })
    } finally {
      restore()
    }
  })

  it('begins a drag again from the finger when the row it sends draws a screen laid out in a new cell', async () => {
    const cell = { width: 8, height: 16 }
    const restore = measured(cell)
    try {
      const { port, controls } = fakeHost()
      controls.holdTerminalMoves()
      const person = await onTerminal(port)
      await waitFor(() => {
        expect(screen.getAllByTestId('mobile-terminal-line').length).toBeGreaterThan(0)
      })
      await person.click(screen.getByRole('button', { name: 'Look around' }))
      finger('pointerdown', 1, 100, 100)
      // A screen laid out in a larger cell has come and is not yet drawn when the finger crosses a
      // row and a half. Sending the row draws it, and the drag begins again from the finger in the
      // larger cell, with no part of the smaller one left.
      act(() => {
        cell.width = 9
        cell.height = 18
        controls.terminalViews[0]?.show()
        screen.getByTestId('mobile-terminal').dispatchEvent(fingerEvent('pointermove', 1, 100, 124))
      })
      expect(gridShift()).toEqual({ x: 0, y: 18 })
      finger('pointerup', 1, 100, 124)
      expect(controls.terminalViews[0]?.moves).toEqual([{ number: 1, across: 0, down: -1 }])
    } finally {
      restore()
    }
  })

  it('ends a drag without sending its part when a second finger comes down, and pinches', async () => {
    const restore = measured()
    try {
      const { port, controls } = fakeHost()
      controls.holdTerminalMoves()
      const person = await onTerminal(port)
      await waitFor(() => {
        expect(screen.getAllByTestId('mobile-terminal-line').length).toBeGreaterThan(0)
      })
      await person.click(screen.getByRole('button', { name: 'Look around' }))
      finger('pointerdown', 1, 100, 100)
      finger('pointermove', 1, 100, 108)
      expect(gridShift()).toEqual({ x: 0, y: 8 })
      finger('pointerdown', 2, 200, 100)
      expect(gridShift()).toEqual({ x: 0, y: 0 })
      finger('pointermove', 2, 260, 100)
      finger('pointerup', 2, 260, 100)
      finger('pointerup', 1, 100, 108)
      expect(await screen.findByText('Zoom 113%')).toBeInTheDocument()
      expect(controls.terminalViews[0]?.moves).toEqual([])
    } finally {
      restore()
    }
  })

  it('sends nothing for a drag whose view has changed under it: control taken, or the view ended', async () => {
    const restore = measured()
    try {
      const { port, controls } = fakeHost()
      controls.holdTerminalMoves()
      const person = await onTerminal(port)
      await waitFor(() => {
        expect(screen.getAllByTestId('mobile-terminal-line').length).toBeGreaterThan(0)
      })
      await person.click(screen.getByRole('button', { name: 'Look around' }))
      // A row and a half down; control is taken with the finger still down, and then it lifts.
      finger('pointerdown', 1, 100, 100)
      finger('pointermove', 1, 100, 124)
      await person.click(screen.getByRole('button', { name: 'Take control' }))
      // The part not sent is gone, and the return is drawn over the row sent: the live screen.
      expect(gridShift()).toEqual({ x: 0, y: 0 })
      finger('pointerup', 1, 100, 124)
      expect(controls.terminalViews[0]?.moves).toEqual([
        { number: 1, across: 0, down: -1 },
        { number: 2, live: true }
      ])

      // The same with the view ending under the finger.
      await person.click(screen.getByRole('button', { name: 'Look around' }))
      finger('pointerdown', 1, 100, 100)
      finger('pointermove', 1, 100, 108)
      act(() => {
        controls.terminalViews[0]?.end('This session has closed.')
      })
      finger('pointermove', 1, 100, 140)
      finger('pointerup', 1, 100, 140)
      expect(controls.terminalViews[0]?.moves).toHaveLength(2)
      expect(gridShift()).toEqual({ x: 0, y: 0 })
    } finally {
      restore()
    }
  })

  it('ignores a finger whose drag a change of view ended until it lifts, and never gives it to the program', async () => {
    const restore = measured()
    try {
      const { port, controls } = fakeHost()
      controls.holdTerminalMoves()
      const typed = vi.spyOn(port, 'terminalInput')
      const person = await onTerminal(port)
      await waitFor(() => {
        expect(screen.getAllByTestId('mobile-terminal-line').length).toBeGreaterThan(0)
      })
      await person.click(screen.getByRole('button', { name: 'Look around' }))
      finger('pointerdown', 1, 100, 100)
      finger('pointermove', 1, 100, 124)
      await person.click(screen.getByRole('button', { name: 'Take control' }))
      finger('pointermove', 1, 100, 180)
      finger('pointerup', 1, 100, 180)
      expect(controls.terminalViews[0]?.moves).toEqual([
        { number: 1, across: 0, down: -1 },
        { number: 2, live: true }
      ])
      expect(typed).not.toHaveBeenCalled()

      // Look around, drag half a row, and take control and look around again without the finger
      // moving: the drag is over, and what it had not sent is gone.
      await person.click(screen.getByRole('button', { name: 'Look around' }))
      finger('pointerdown', 2, 100, 100)
      finger('pointermove', 2, 100, 108)
      expect(gridShift()).toEqual({ x: 0, y: 8 })
      await person.click(screen.getByRole('button', { name: 'Take control' }))
      await person.click(screen.getByRole('button', { name: 'Look around' }))
      expect(gridShift()).toEqual({ x: 0, y: 0 })
      finger('pointermove', 2, 100, 140)
      finger('pointerup', 2, 100, 140)
      expect(controls.terminalViews[0]?.moves).toEqual([
        { number: 1, across: 0, down: -1 },
        { number: 2, live: true },
        { number: 3, live: true }
      ])
      expect(typed).not.toHaveBeenCalled()
    } finally {
      restore()
    }
  })

  it('offers labelled controls in view mode that move the window a page at a time', async () => {
    const { port, controls } = fakeHost()
    controls.holdTerminalMoves()
    const person = await onTerminal(port)
    await waitFor(() => {
      expect(screen.getAllByTestId('mobile-terminal-line').length).toBeGreaterThan(0)
    })
    expect(screen.queryByRole('button', { name: 'Move the window up' })).toBeNull()
    await person.click(screen.getByRole('button', { name: 'Look around' }))
    const up = screen.getByRole('button', { name: 'Move the window up' })
    expect(screen.getByRole('button', { name: 'Move the window down' })).toBeDisabled()
    await person.click(up)
    expect(controls.terminalViews[0]?.moves).toEqual([{ number: 1, across: 0, down: -8 }])
  })

  it("takes a press in view mode from the browser, so it starts no selection or native drag, and leaves control mode's alone", async () => {
    const { port } = fakeHost()
    const person = await onTerminal(port)
    await waitFor(() => {
      expect(screen.getAllByTestId('mobile-terminal-line').length).toBeGreaterThan(0)
    })
    /** Whether the view kept the browser from its own way with `event`, sent over the terminal. */
    const kept = (event: Event, target: Element = screen.getByTestId('mobile-terminal')): boolean => {
      act(() => {
        target.dispatchEvent(event)
      })
      return event.defaultPrevented
    }
    const dragOfText = () => new Event('dragstart', { bubbles: true, cancelable: true })
    const line = () => screen.getAllByTestId('mobile-terminal-line')[0] ?? document.body
    // Control mode: the press and a drag of selected text are the browser's, as before.
    expect(kept(fingerEvent('pointerdown', 1, 100, 100, 'mouse'))).toBe(false)
    kept(fingerEvent('pointerup', 1, 100, 100, 'mouse'))
    expect(kept(dragOfText(), line())).toBe(false)
    // View mode: a press of a finger or a mouse, and a drag of text selected before, are the view's.
    await person.click(screen.getByRole('button', { name: 'Look around' }))
    expect(kept(fingerEvent('pointerdown', 2, 100, 100, 'mouse'))).toBe(true)
    kept(fingerEvent('pointerup', 2, 100, 100, 'mouse'))
    expect(kept(fingerEvent('pointerdown', 3, 100, 100))).toBe(true)
    kept(fingerEvent('pointerup', 3, 100, 100))
    expect(kept(dragOfText(), line())).toBe(true)
  })

  it('gives a one-finger drag to the program in control mode and moves nothing', async () => {
    const restore = measured()
    try {
      const { port, controls } = fakeHost()
      const sent = vi.spyOn(port, 'terminalInput')
      await onTerminal(port)
      await waitFor(() => {
        expect(screen.getAllByTestId('mobile-terminal-line').length).toBeGreaterThan(0)
      })
      finger('pointerdown', 1, 100, 164)
      finger('pointermove', 1, 100, 100)
      finger('pointerup', 1, 100, 100)
      await waitFor(() => {
        expect(sent).toHaveBeenCalled()
      })
      expect(controls.terminalViews[0]?.moves).toEqual([])
      expect(gridShift()).toEqual({ x: 0, y: 0 })
    } finally {
      restore()
    }
  })

  it('folds the composer to one line with Send beside it while the terminal shows, and leaves the picker to the conversation', async () => {
    const { port } = fakeHost()
    const person = userEvent.setup()
    render(
      <AppProvider port={port}>
        <OnSession sessionId={SESSION_MAIN} />
      </AppProvider>
    )
    const empty = 'Write something, or add an attachment.'
    expect(screen.getByRole('group', { name: 'Add an attachment' })).toBeInTheDocument()
    expect(screen.getByText(empty)).toBeInTheDocument()

    await person.click(screen.getByRole('tab', { name: 'Terminal' }))
    const field = screen.getByLabelText('Message this session')
    expect(field).toHaveAttribute('rows', '1')
    expect(field.parentElement).toContainElement(screen.getByRole('button', { name: 'Send' }))
    // An empty draft needs no words while Send stands disabled beside it, and attachments are
    // added in the conversation.
    expect(screen.queryByRole('group', { name: 'Add an attachment' })).toBeNull()
    expect(screen.queryByText(empty)).toBeNull()
    expect(field).not.toHaveAttribute('aria-describedby')

    await person.click(screen.getByRole('tab', { name: 'Conversation' }))
    expect(screen.getByRole('group', { name: 'Add an attachment' })).toBeInTheDocument()
    expect(screen.getByText(empty)).toBeInTheDocument()
  })

  it('keeps every other reason Send is held back beside the folded field', async () => {
    const { port } = fakeHost()
    // The one answer that means nobody knows what became of a submission.
    const uncertain = {
      ...port,
      composerSubmit: () =>
        Promise.reject({
          code: 'OUTCOME_UNKNOWN',
          message: 'The host did not say what became of it.',
          user_action: 'ask'
        })
    }
    const person = await onTerminal(uncertain)
    const field = screen.getByLabelText('Message this session')
    await person.type(field, 'ls')
    await person.click(screen.getByRole('button', { name: 'Send' }))
    const reason = await screen.findByText(/no confirmed outcome yet/)
    expect(field).toHaveAttribute('aria-describedby', reason.id)
    expect(screen.getByRole('button', { name: 'Send' })).toBeDisabled()
  })

  it('lets the bar yield while a keyboard covers part of the session, and not for what lies under it', async () => {
    const { port } = fakeHost()
    // jsdom lays nothing out: a window 800 pixels high, and a session that ends 90 pixels above its
    // bottom, over the shell's padding and its tab bar.
    const window800 = Object.getOwnPropertyDescriptor(window, 'innerHeight')
    Object.defineProperty(window, 'innerHeight', { configurable: true, value: 800 })
    const rects = vi.spyOn(Element.prototype, 'getBoundingClientRect').mockImplementation(function (
      this: Element
    ) {
      return this.classList.contains('m-session')
        ? DOMRect.fromRect({ x: 0, y: 100, width: 390, height: 610 })
        : new DOMRect()
    })
    const root = document.documentElement
    try {
      await onTerminal(port)
      const session = document.querySelector<HTMLElement>('.m-session')
      expect(session?.style.getPropertyValue('--under-session')).toBe('90px')
      expect(session).not.toHaveAttribute('data-keyboard')
      // A keyboard that covers no more than what lies under the session covers none of it.
      act(() => {
        root.style.setProperty('--keyboard', '80px')
      })
      await act(async () => {
        await Promise.resolve()
      })
      expect(session).not.toHaveAttribute('data-keyboard')
      act(() => {
        root.style.setProperty('--keyboard', '300px')
      })
      await waitFor(() => {
        expect(session).toHaveAttribute('data-keyboard')
      })
      act(() => {
        root.style.removeProperty('--keyboard')
      })
      await waitFor(() => {
        expect(session).not.toHaveAttribute('data-keyboard')
      })
    } finally {
      rects.mockRestore()
      root.style.removeProperty('--keyboard')
      if (window800 === undefined) Reflect.deleteProperty(window, 'innerHeight')
      else Object.defineProperty(window, 'innerHeight', window800)
    }
  })

  it('says in two lines what the view is doing, and all of it when asked', async () => {
    const { port } = fakeHost()
    const person = await onTerminal(port)
    await waitFor(() => {
      expect(screen.getAllByTestId('mobile-terminal-line')).toHaveLength(8)
    })
    const more = screen.getByRole('button', { name: 'More' })
    const status = document.getElementById(more.getAttribute('aria-controls') ?? '')
    expect(more).toHaveAttribute('aria-expanded', 'false')
    expect(status).toHaveAttribute('data-expanded', 'false')
    // All of it is there for a screen reader either way: the warnings, the mode's sentence and the
    // host's presentation.
    expect(status).toContainElement(screen.getByTestId('substituted-count'))
    expect(status).toContainElement(screen.getByTestId('terminal-presentation'))
    expect(status?.textContent).toContain(describeMode('control'))

    await person.click(more)
    expect(screen.getByRole('button', { name: 'Less' })).toHaveAttribute('aria-expanded', 'true')
    expect(status).toHaveAttribute('data-expanded', 'true')
    await person.click(screen.getByRole('button', { name: 'Less' }))
    expect(screen.getByRole('button', { name: 'More' })).toHaveAttribute('aria-expanded', 'false')
  })

  it('keeps its controls in keyboard order: the mode, the moves, the status, the keys and the field, with Send after it', async () => {
    const { port } = fakeHost()
    const person = await onTerminal(port)
    await waitFor(() => {
      expect(screen.getAllByTestId('mobile-terminal-line')).toHaveLength(8)
    })
    await person.click(screen.getByRole('button', { name: 'Look around' }))
    await person.type(screen.getByLabelText('Message this session'), 'ls')
    screen.getByRole('button', { name: 'Take control' }).focus()
    const reached: string[] = []
    for (let step = 0; step < 24; step += 1) {
      await person.tab()
      const focused = document.activeElement
      reached.push(
        focused?.tagName === 'TEXTAREA'
          ? 'the field'
          : (focused?.getAttribute('aria-label') ?? focused?.textContent ?? '')
      )
    }
    const at = (name: string) => reached.indexOf(name)
    expect(at('Move the window up')).toBe(0)
    expect(at('More')).toBeGreaterThan(at('Move the window up'))
    expect(at('Escape')).toBe(at('More') + 1)
    expect(at('the field')).toBeGreaterThan(at('Escape'))
    // The field gives Tab to the program, so Send is found as the next control after the field
    // in the order a keyboard moves through the page.
    const field = screen.getByLabelText('Message this session')
    const controls = Array.from(document.querySelectorAll<HTMLElement>('button:not([disabled]), textarea'))
    expect(controls[controls.indexOf(field) + 1]).toBe(screen.getByRole('button', { name: 'Send' }))
  })

  it('ends with the host words and attaches again when asked', async () => {
    const { port, controls } = fakeHost()
    const person = await onTerminal(port)
    await waitFor(() => {
      expect(screen.getAllByTestId('mobile-terminal-line')).toHaveLength(8)
    })
    act(() => {
      controls.terminalViews[0]?.end('This view was detached from the session.')
    })
    expect(screen.getByText('This view was detached from the session.')).toBeInTheDocument()
    // The last frame stays beneath the words.
    expect(screen.getAllByTestId('mobile-terminal-line')).toHaveLength(8)
    await person.click(screen.getByTestId('attach-again'))
    await waitFor(() => {
      expect(controls.terminalViews).toHaveLength(2)
    })
    await waitFor(() => {
      expect(screen.queryByText('This view was detached from the session.')).toBeNull()
    })
  })
})
