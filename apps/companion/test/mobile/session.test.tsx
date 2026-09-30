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
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { AppProvider } from '../../src/app/state'
import { fakeHost, LOST_CONTROL, terminalScreen, type HeldReads } from '../../src/host/fake'
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

    // The view changes session before the first read answers.
    rerender(onSession(SESSION_BUILD))
    await made(held, 2)

    // The build session's read finds its entry and reads on from after it before it is done.
    await answer(held, 1)
    await made(held, 3)
    await answer(held, 2)
    expect(screen.getByText('Claude Code started.')).toBeInTheDocument()
    await answer(held, 0)
    expect(screen.queryByText('Find why the reconnect test is flaky.')).toBeNull()
    expect(screen.getByText('Claude Code started.')).toBeInTheDocument()
    held.release()
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
    // The read that finds the history reads on from after it before it is done.
    await answer(held, 0)
    await made(held, 2)
    expect(screen.getByText('Reading the conversation…')).toBeInTheDocument()
    await answer(held, 1)
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

describe("the phone's composer and the conversation it writes to (KR-REQ-13.12)", () => {
  it('asks before sending a draft to a conversation that moved on while it was written', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    const sent: string[] = []
    render(
      <AppProvider
        port={{
          ...port,
          composerSubmit: (params) => {
            sent.push(params.target.binding_revision)
            return port.composerSubmit(params)
          }
        }}
      >
        <OnSession sessionId={SESSION_MAIN} />
      </AppProvider>
    )
    await screen.findByText('Find why the reconnect test is flaky.')
    await person.type(screen.getByLabelText('Message this session'), 'Keep the timer')

    // The agent moves to another conversation, and the view reads it again, as it does when the
    // host is heard from.
    controls.records.moveBinding(SESSION_MAIN)
    act(() => {
      controls.setConnected(true)
    })
    await waitFor(() => {
      expect(screen.getByText(/The conversation changed since this was written/)).toBeInTheDocument()
    })
    expect(screen.getByRole('button', { name: 'Send' })).toBeDisabled()
    expect(screen.getByLabelText('Message this session')).toHaveValue('Keep the timer')

    await person.click(screen.getByTestId('composer-retarget'))
    await person.click(screen.getByRole('button', { name: 'Send' }))
    await waitFor(() => {
      expect(sent).toEqual(['5'])
    })
  })

  it('keeps a draft written before the agent was read to the first conversation it learns', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    const held = controls.hold('agentSnapshot')
    render(
      <AppProvider port={port}>
        <OnSession sessionId={SESSION_MAIN} />
      </AppProvider>
    )
    await made(held, 1)
    await person.type(screen.getByLabelText('Message this session'), 'Written early')
    held.release()
    await screen.findByText('Find why the reconnect test is flaky.')

    controls.records.moveBinding(SESSION_MAIN)
    act(() => {
      controls.setConnected(true)
    })
    await waitFor(() => {
      expect(screen.getByText(/The conversation changed since this was written/)).toBeInTheDocument()
    })
    expect(screen.getByRole('button', { name: 'Send' })).toBeDisabled()
  })

  it('says why the agent will not take a prompt, in its own words', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    controls.records.suspend(SESSION_MAIN, 'The conversation changed outside this host.')
    render(
      <AppProvider port={port}>
        <OnSession sessionId={SESSION_MAIN} />
      </AppProvider>
    )
    await screen.findByText('Find why the reconnect test is flaky.')
    await person.type(screen.getByLabelText('Message this session'), 'go on')
    expect(await screen.findByText('The conversation changed outside this host.')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Send' })).toBeDisabled()
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
      'the terminal profile its client declared is not one this build has qualified'
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
      // Two fingers 100 pixels apart move to 160: a pinch outwards to 1.6 times, which leaves the
      // text at the step nearest that.
      finger('pointerdown', 1, 100)
      finger('pointerdown', 2, 200)
      finger('pointermove', 2, 260)
      finger('pointerup', 2, 260)
      finger('pointerup', 1, 100)
      expect(await screen.findByText('Zoom 150%')).toBeInTheDocument()
      // Cells of 12 by 24 now: 26 across and 16 down.
      await waitFor(() => {
        expect(controls.terminalViews[0]?.grids.at(-1)).toEqual({ columns: 26, rows: 16 })
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

  /**
   * Gives the phone's view what a browser measures: cells of 8 by 16 pixels, a surface 336 by 420
   * pixels at the page's corner, and inside it the grid with 8 pixels of padding, moved by its own
   * transform and its drag layer's, as a browser reports a transformed box. Returns what puts them
   * back.
   */
  function laidOutPhone(): () => void {
    const ownStyle = window.getComputedStyle.bind(window)
    const rects = vi.spyOn(Element.prototype, 'getBoundingClientRect').mockImplementation(function (
      this: Element
    ) {
      const element = this as HTMLElement
      const text = element.textContent ?? ''
      if (element.getAttribute('aria-hidden') === 'true' && /^M+$/.test(text)) {
        return DOMRect.fromRect({ x: 0, y: 0, width: text.length * 8, height: 16 })
      }
      if (element.dataset.testid === 'mobile-terminal') {
        return DOMRect.fromRect({ x: 0, y: 0, width: 336, height: 420 })
      }
      if (element.classList.contains('m-terminal-grid')) {
        const own = translation(element)
        const layer = translation(element.parentElement)
        return DOMRect.fromRect({ x: own.x + layer.x, y: own.y + layer.y, width: 336, height: 420 })
      }
      return new DOMRect()
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
            paddingBottom: '8px',
            borderLeftWidth: '0px',
            borderTopWidth: '0px',
            lineHeight: '16px',
            fontSize: '12px'
          } as CSSStyleDeclaration)
        : ownStyle(element, pseudo)
    )
    return () => {
      rects.mockRestore()
      widths.mockRestore()
      heights.mockRestore()
      styles.mockRestore()
    }
  }

  /** Takes control of the first view, as the person does, and has the session grant it. */
  async function takeControl(
    person: ReturnType<typeof userEvent.setup>,
    controls: ReturnType<typeof fakeHost>['controls']
  ): Promise<void> {
    await person.click(screen.getByRole('button', { name: 'Take control' }))
    // A held take is granted here; one that is not has been, or is granted by itself.
    act(() => {
      controls.terminalViews[0]?.grantControl()
    })
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Look around' })).toBeInTheDocument()
      expect(controls.terminalViews[0]?.control.state).toBe('controlling')
    })
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Escape' })).toBeEnabled()
    })
  }

  /** Every wheel turn, key, text and paste the first view took for the program, in order. */
  function programInputs(controls: ReturnType<typeof fakeHost>['controls']) {
    return (controls.terminalViews[0]?.inputs ?? []).filter(
      (input) => input.kind !== 'take' && input.kind !== 'release'
    )
  }

  /** A key's press or release under take 1, named as the page names it, with nothing held unless told. */
  function key(name: string, event: 'press' | 'release', over: Record<string, unknown> = {}) {
    return {
      kind: 'key',
      take: 1,
      event,
      key: name,
      base: [...name].length === 1 ? name : null,
      keypad: null,
      shift: false,
      alt: false,
      control: false,
      caps_lock: false,
      num_lock: false,
      ...over
    }
  }

  /** The program's keyboard, or null while the field is the draft's. */
  const programKeyboard = () => screen.queryByLabelText<HTMLTextAreaElement>('Type to the program')

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
      await onTerminal(port)
      await waitFor(() => {
        expect(screen.getAllByTestId('mobile-terminal-line').length).toBeGreaterThan(0)
      })
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
      await onTerminal(port)
      await waitFor(() => {
        expect(screen.getAllByTestId('mobile-terminal-line').length).toBeGreaterThan(0)
      })
      finger('pointerdown', 1, 100, 100)
      finger('pointermove', 1, 100, 108)
      expect(gridShift()).toEqual({ x: 0, y: 8 })
      finger('pointerdown', 2, 200, 100)
      expect(gridShift()).toEqual({ x: 0, y: 0 })
      finger('pointermove', 2, 260, 100)
      finger('pointerup', 2, 260, 100)
      finger('pointerup', 1, 100, 108)
      expect(await screen.findByText('Zoom 150%')).toBeInTheDocument()
      expect(controls.terminalViews[0]?.moves).toEqual([])
    } finally {
      restore()
    }
  })

  // KR-REQ-13.06, 13.17: gesture motion tracks the finger and can reverse during the movement. The
  // text scales with the fingers while they pinch, follows them back when they reverse, and the zoom
  // changes once, to the step nearest where they end; a pinch that comes back where it began changes
  // nothing.
  it('scales the text with the fingers while they pinch, and follows them back', async () => {
    const restore = measured()
    try {
      const { port } = fakeHost()
      await onTerminal(port)
      await waitFor(() => {
        expect(screen.getAllByTestId('mobile-terminal-line').length).toBeGreaterThan(0)
      })
      const layer = () =>
        screen.getByTestId('mobile-terminal').querySelector<HTMLElement>('.m-terminal-grid')?.parentElement
      const scaled = () => /scale\(([\d.]+)\)/.exec(layer()?.style.transform ?? '')?.[1] ?? '1'
      finger('pointerdown', 1, 100, 100)
      finger('pointerdown', 2, 200, 100)
      finger('pointermove', 2, 250, 100)
      expect(scaled()).toBe('1.5')
      // Towards each other: smaller, but never past the smallest step.
      finger('pointermove', 2, 150, 100)
      expect(scaled()).toBe('0.75')
      // Back where they began.
      finger('pointermove', 2, 200, 100)
      expect(scaled()).toBe('1')
      finger('pointerup', 2, 200, 100)
      finger('pointerup', 1, 100, 100)
      expect(layer()?.style.transform).toBe('')
      expect(screen.getByText('Zoom 100%')).toBeInTheDocument()
    } finally {
      restore()
    }
  })

  // The nearest step decides, however small the pinch: a pinch to 107% is nearer 112.5% than 100%,
  // and one to 104% is nearer 100%, so it changes nothing.
  it('settles a small pinch on the step nearest where the fingers ended', async () => {
    const restore = measured()
    try {
      const { port } = fakeHost()
      await onTerminal(port)
      await waitFor(() => {
        expect(screen.getAllByTestId('mobile-terminal-line').length).toBeGreaterThan(0)
      })
      finger('pointerdown', 1, 100, 100)
      finger('pointerdown', 2, 200, 100)
      finger('pointermove', 2, 204, 100)
      finger('pointerup', 2, 204, 100)
      finger('pointerup', 1, 100, 100)
      expect(screen.getByText('Zoom 100%')).toBeInTheDocument()
      finger('pointerdown', 1, 100, 100)
      finger('pointerdown', 2, 200, 100)
      finger('pointermove', 2, 207, 100)
      finger('pointerup', 2, 207, 100)
      finger('pointerup', 1, 100, 100)
      expect(screen.getByText('Zoom 113%')).toBeInTheDocument()
    } finally {
      restore()
    }
  })

  // Nothing on the wire carries a pinch, so a pinch takes nothing from the program: it zooms in
  // control mode as it does in view mode.
  it('zooms with a pinch in control mode too', async () => {
    const restore = measured()
    try {
      const { port } = fakeHost()
      const person = await onTerminal(port)
      await waitFor(() => {
        expect(screen.getAllByTestId('mobile-terminal-line').length).toBeGreaterThan(0)
      })
      await person.click(screen.getByRole('button', { name: 'Take control' }))
      await screen.findByRole('button', { name: 'Look around' })
      finger('pointerdown', 1, 100, 100)
      finger('pointerdown', 2, 200, 100)
      finger('pointermove', 2, 160, 100)
      finger('pointerup', 2, 160, 100)
      finger('pointerup', 1, 100, 100)
      expect(screen.getByText('Zoom 75%')).toBeInTheDocument()
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
      const person = await onTerminal(port)
      await waitFor(() => {
        expect(screen.getAllByTestId('mobile-terminal-line').length).toBeGreaterThan(0)
      })
      finger('pointerdown', 1, 100, 100)
      finger('pointermove', 1, 100, 124)
      await person.click(screen.getByRole('button', { name: 'Take control' }))
      finger('pointermove', 1, 100, 180)
      finger('pointerup', 1, 100, 180)
      expect(controls.terminalViews[0]?.moves).toEqual([
        { number: 1, across: 0, down: -1 },
        { number: 2, live: true }
      ])
      expect(programInputs(controls)).toEqual([])

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
      expect(programInputs(controls)).toEqual([])
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
    const up = screen.getByRole('button', { name: 'Move the window up' })
    expect(screen.getByRole('button', { name: 'Move the window down' })).toBeDisabled()
    await person.click(up)
    expect(controls.terminalViews[0]?.moves).toEqual([{ number: 1, across: 0, down: -8 }])
    await person.click(screen.getByRole('button', { name: 'Take control' }))
    expect(screen.queryByRole('button', { name: 'Move the window up' })).toBeNull()
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
    // View mode, where a view opens: a press of a finger or a mouse, and a drag of text selected
    // before, are the view's.
    expect(kept(fingerEvent('pointerdown', 2, 100, 100, 'mouse'))).toBe(true)
    kept(fingerEvent('pointerup', 2, 100, 100, 'mouse'))
    expect(kept(fingerEvent('pointerdown', 3, 100, 100))).toBe(true)
    kept(fingerEvent('pointerup', 3, 100, 100))
    expect(kept(dragOfText(), line())).toBe(true)
    // Control mode: the press and a drag of selected text are the browser's, as before.
    await person.click(screen.getByRole('button', { name: 'Take control' }))
    expect(kept(fingerEvent('pointerdown', 1, 100, 100, 'mouse'))).toBe(false)
    kept(fingerEvent('pointerup', 1, 100, 100, 'mouse'))
    expect(kept(dragOfText(), line())).toBe(false)
  })

  it("turns the program's wheel with a one-finger drag in control mode, a turn a row at the cell under the finger", async () => {
    const restore = laidOutPhone()
    try {
      const { port, controls } = fakeHost()
      const person = await onTerminal(port)
      await waitFor(() => {
        expect(screen.getAllByTestId('mobile-terminal-line').length).toBeGreaterThan(0)
      })
      await takeControl(person, controls)
      // The grid's content box starts 8 pixels in, in cells of 8 by 16: the finger goes down on
      // column 5 of row 6, crosses a row up, then another and a half, then back down past its start.
      finger('pointerdown', 1, 49, 105)
      finger('pointermove', 1, 49, 89)
      finger('pointermove', 1, 49, 65)
      finger('pointermove', 1, 49, 125)
      finger('pointerup', 1, 49, 125)
      // Each turn goes once the one before is answered.
      await waitFor(() => {
        expect(programInputs(controls)).toEqual([
          { kind: 'wheel', take: 1, column: 5, line: 5, turns: 1, shift: false, alt: false, control: false },
          { kind: 'wheel', take: 1, column: 5, line: 3, turns: 1, shift: false, alt: false, control: false },
          { kind: 'wheel', take: 1, column: 5, line: 7, turns: -3, shift: false, alt: false, control: false }
        ])
      })
      // Nothing of it was an arrow key, and nothing moved the window.
      expect(programInputs(controls).some((input) => input.kind === 'key')).toBe(false)
      expect(controls.terminalViews[0]?.moves).toEqual([{ number: 1, live: true }])
      expect(gridShift()).toEqual({ x: 0, y: 0 })

      // A tap sends nothing; nor do the rows a finger crosses outside the grid, and a cancelled
      // drag or a second finger ends the turning.
      finger('pointerdown', 2, 49, 105)
      finger('pointermove', 2, 49, 110)
      finger('pointerup', 2, 49, 110)
      finger('pointerdown', 3, 49, 105)
      finger('pointermove', 3, 49, 500)
      finger('pointercancel', 3, 49, 500)
      finger('pointerdown', 4, 49, 105)
      finger('pointerdown', 5, 200, 105)
      finger('pointermove', 4, 49, 40)
      finger('pointerup', 5, 200, 105)
      finger('pointerup', 4, 49, 40)
      await act(async () => {
        await new Promise((resolve) => {
          setTimeout(resolve, 0)
        })
      })
      expect(programInputs(controls)).toHaveLength(3)
    } finally {
      restore()
    }
  })

  it('sends nothing while the program does not use the wheel, and says so', async () => {
    const restore = laidOutPhone()
    try {
      const { port, controls } = fakeHost()
      controls.terminalWheel('unreported')
      const person = await onTerminal(port)
      await waitFor(() => {
        expect(screen.getAllByTestId('mobile-terminal-line').length).toBeGreaterThan(0)
      })
      await takeControl(person, controls)
      expect(
        screen.getByText('Control: your keys go to the program, which is not using the wheel. Look around to scroll.')
      ).toBeInTheDocument()
      finger('pointerdown', 1, 49, 105)
      finger('pointermove', 1, 49, 40)
      finger('pointerup', 1, 49, 40)
      expect(programInputs(controls)).toEqual([])
      expect(controls.terminalViews[0]?.moves).toEqual([{ number: 1, live: true }])
    } finally {
      restore()
    }
  })

  it('keeps the terminal keys for control: disabled while the view watches, sent under the take while it controls', async () => {
    const { port, controls } = fakeHost()
    controls.holdTerminalControl()
    const person = await onTerminal(port)
    await waitFor(() => {
      expect(screen.getAllByTestId('mobile-terminal-line').length).toBeGreaterThan(0)
    })
    const escape = () => screen.getByRole('button', { name: 'Escape' })
    // Watching: the keys wait for control, and the field is the draft's, with keys of its own.
    expect(escape()).toBeDisabled()
    screen.getByLabelText('Message this session').focus()
    await person.keyboard('{ArrowUp}')
    expect(programInputs(controls)).toEqual([])
    expect(programKeyboard()).toBeNull()
    // Taking: still nothing reaches the program.
    await person.click(screen.getByRole('button', { name: 'Take control' }))
    expect(screen.getByText('Asking the session for control…')).toBeInTheDocument()
    expect(escape()).toBeDisabled()
    expect(programKeyboard()).toBeNull()
    act(() => {
      controls.terminalViews[0]?.grantControl()
    })
    await waitFor(() => {
      expect(escape()).toBeEnabled()
    })
    // A tap on a key is its press and its release; a key typed in the field is named the same way.
    await person.click(escape())
    programKeyboard()?.focus()
    await person.keyboard('{ArrowUp}')
    await waitFor(() => {
      expect(programInputs(controls)).toEqual([
        key('Escape', 'press'),
        key('Escape', 'release'),
        key('ArrowUp', 'press'),
        key('ArrowUp', 'release')
      ])
    })
    expect(screen.getByText('Control: your keys and drags go to the program in this terminal.')).toBeInTheDocument()
  })

  it('makes the field the program keyboard while the view controls it, and gives the draft back when control ends', async () => {
    const { port, controls } = fakeHost()
    const person = await onTerminal(port)
    await waitFor(() => {
      expect(screen.getAllByTestId('mobile-terminal-line').length).toBeGreaterThan(0)
    })
    await person.type(screen.getByLabelText('Message this session'), 'a draft')
    await takeControl(person, controls)
    // The field's place holds the program's keyboard, which says what it is where a placeholder
    // would; Send goes with the draft.
    const keyboard = programKeyboard()
    expect(keyboard).not.toBeNull()
    expect(screen.queryByLabelText('Message this session')).toBeNull()
    expect(screen.queryByRole('button', { name: 'Send' })).toBeNull()
    expect(keyboard?.parentElement?.textContent).toContain('Type to the program')
    expect(keyboard).toHaveAttribute('autocapitalize', 'off')
    expect(keyboard).toHaveAttribute('autocorrect', 'off')
    expect(keyboard).toHaveAttribute('spellcheck', 'false')
    expect(keyboard).toHaveAccessibleDescription('Tab goes to the program; Control-Tab moves on.')
    // Text a software keyboard commits goes as text, and the field stays empty of it.
    act(() => {
      if (keyboard === null) return
      keyboard.value = '\u200bls'
      keyboard.dispatchEvent(new InputEvent('input', { bubbles: true, inputType: 'insertText', data: 'ls' }))
    })
    await waitFor(() => {
      expect(programInputs(controls)).toEqual([{ kind: 'text', take: 1, text: 'ls' }])
    })
    await person.click(screen.getByRole('button', { name: 'Look around' }))
    expect(programKeyboard()).toBeNull()
    expect(screen.getByLabelText('Message this session')).toHaveValue('a draft')
    expect(screen.getByRole('button', { name: 'Send' })).toBeEnabled()
  })

  it("sends the row's keys with what the row holds for them and the locks of the tap, and lets a modifier held for one key go", async () => {
    const { port, controls } = fakeHost()
    const person = await onTerminal(port)
    await waitFor(() => {
      expect(screen.getAllByTestId('mobile-terminal-line').length).toBeGreaterThan(0)
    })
    await takeControl(person, controls)
    const control = () => screen.getByRole('button', { name: /^Control,/ })
    await person.click(control())
    expect(control()).toHaveAccessibleName('Control, held for the next key')
    await person.click(screen.getByRole('button', { name: 'Tab' }))
    expect(control()).toHaveAccessibleName('Control, off')
    // A key typed on a keyboard in the field takes what the row holds for it, too.
    await person.click(control())
    programKeyboard()?.focus()
    await person.keyboard('c')
    expect(control()).toHaveAccessibleName('Control, off')
    // The lock state comes from the tap itself.
    fireEvent.click(screen.getByRole('button', { name: 'Vertical bar' }), { modifierCapsLock: true })
    await waitFor(() => {
      expect(programInputs(controls)).toEqual([
        key('Tab', 'press', { control: true }),
        key('Tab', 'release', { control: true }),
        key('c', 'press', { control: true }),
        key('c', 'release', { control: true }),
        key('|', 'press', { caps_lock: true }),
        key('|', 'release', { caps_lock: true })
      ])
    })
  })

  it('gives Tab in the field to the program only while the view controls it, and moves on with Control-Tab', async () => {
    const { port, controls } = fakeHost()
    const person = await onTerminal(port)
    await waitFor(() => {
      expect(screen.getAllByTestId('mobile-terminal-line').length).toBeGreaterThan(0)
    })
    await person.type(screen.getByLabelText('Message this session'), 'ls')
    // Watching: Tab in the draft's field moves on to Send.
    await person.tab()
    expect(screen.getByRole('button', { name: 'Send' })).toHaveFocus()
    await takeControl(person, controls)
    const keyboard = programKeyboard()
    keyboard?.focus()
    await person.keyboard('{Tab}{Shift>}{Tab}{/Shift}')
    expect(keyboard).toHaveFocus()
    await waitFor(() => {
      expect(programInputs(controls)).toEqual([
        key('Tab', 'press'),
        key('Tab', 'release'),
        key('Tab', 'press', { shift: true }),
        key('Tab', 'release', { shift: true })
      ])
    })
    // Control-Shift-Tab moves back to the last of the terminal keys, sending nothing.
    await person.keyboard('{Control>}{Shift>}{Tab}{/Shift}{/Control}')
    expect(screen.getByRole('button', { name: 'Tilde' })).toHaveFocus()
    expect(programInputs(controls)).toHaveLength(4)
  })

  it('says why a key did not reach the program beside its keyboard, until a key that goes', async () => {
    const { port, controls } = fakeHost()
    controls.holdTerminalViews()
    controls.holdTerminalMoves()
    const person = await onTerminal(port)
    await waitFor(() => {
      expect(controls.terminalViews).toHaveLength(1)
    })
    act(() => {
      controls.terminalViews[0]?.attach()
    })
    await person.click(screen.getByRole('button', { name: 'Take control' }))
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Escape' })).toBeEnabled()
    })
    const keyboard = programKeyboard()
    if (keyboard === null) throw new Error('no program keyboard')
    fireEvent.keyDown(keyboard, { key: 'q', code: 'KeyQ' })
    const refused = "That key did not reach the program: the view is waiting for the session's screen."
    // Above the field, which stays in view with a software keyboard up, and in the field's own
    // status for a screen reader; not in the bar, which a software keyboard hides.
    await waitFor(() => {
      expect(screen.getAllByText(refused)).toHaveLength(2)
    })
    expect(keyboard.parentElement?.querySelector('[role="status"]')?.textContent).toBe(refused)
    expect(document.querySelector('.m-terminal-hud')?.textContent).not.toContain(refused)
    act(() => {
      controls.terminalViews[0]?.show()
    })
    // The release of the refused press is taken and writes nothing: the words stay.
    fireEvent.keyUp(keyboard, { key: 'q', code: 'KeyQ' })
    await act(async () => {
      await new Promise((resolve) => {
        setTimeout(resolve, 0)
      })
    })
    expect(screen.getAllByText(refused)).toHaveLength(2)
    await person.click(screen.getByRole('button', { name: 'Escape' }))
    await waitFor(() => {
      expect(screen.queryByText(refused)).toBeNull()
    })
    expect(programInputs(controls)).toEqual([
      key('q', 'release'),
      key('Escape', 'press'),
      key('Escape', 'release')
    ])
  })

  it('moves the focus to Attach again when the view ends with it in the program keyboard or on a terminal key', async () => {
    for (const where of ['keyboard', 'key'] as const) {
      const { port, controls } = fakeHost()
      const person = await onTerminal(port)
      await waitFor(() => {
        expect(screen.getAllByTestId('mobile-terminal-line').length).toBeGreaterThan(0)
      })
      await takeControl(person, controls)
      if (where === 'keyboard') programKeyboard()?.focus()
      else screen.getByRole('button', { name: 'Escape' }).focus()
      act(() => {
        controls.terminalViews[0]?.end('The session ended.')
      })
      await waitFor(() => {
        expect(screen.getByRole('button', { name: 'Attach again' })).toHaveFocus()
      })
      expect(screen.getByRole('button', { name: 'Take control' })).toBeDisabled()
      cleanup()
    }
  })

  it('moves the focus from the mode button to Attach again when the view ends', async () => {
    const { port, controls } = fakeHost()
    const person = await onTerminal(port)
    await waitFor(() => {
      expect(screen.getAllByTestId('mobile-terminal-line').length).toBeGreaterThan(0)
    })
    await takeControl(person, controls)
    screen.getByRole('button', { name: 'Look around' }).focus()
    act(() => {
      controls.terminalViews[0]?.end('The session ended.')
    })
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Attach again' })).toHaveFocus()
    })
  })

  it('puts the focus on the mode button when Attach again is pressed from the keyboard, and leaves it where a pointer left it', async () => {
    for (const by of ['pointer', 'keyboard'] as const) {
      const { port, controls } = fakeHost()
      const person = await onTerminal(port)
      await waitFor(() => {
        expect(screen.getAllByTestId('mobile-terminal-line').length).toBeGreaterThan(0)
      })
      act(() => {
        controls.terminalViews[0]?.end('The session ended.')
      })
      const again = screen.getByRole('button', { name: 'Attach again' })
      if (by === 'keyboard') {
        again.focus()
        await person.keyboard('{Enter}')
      } else {
        await person.click(again)
      }
      await waitFor(() => {
        expect(controls.terminalViews).toHaveLength(2)
      })
      await waitFor(() => {
        expect(screen.getAllByTestId('mobile-terminal-line').length).toBeGreaterThan(0)
      })
      expect(screen.queryByTestId('attach-again'), by).toBeNull()
      if (by === 'keyboard') {
        expect(screen.getByRole('button', { name: 'Take control' }), by).toHaveFocus()
      } else {
        expect(document.activeElement, by).toBe(document.body)
      }
      cleanup()
    }
  })

  it('puts the focus on the mode button when the view opens again by itself from Attach again, after a pointer press of it', async () => {
    const { port, controls } = fakeHost()
    const person = await onTerminal(port)
    await waitFor(() => {
      expect(screen.getAllByTestId('mobile-terminal-line').length).toBeGreaterThan(0)
    })
    act(() => {
      controls.terminalViews[0]?.end('The session ended.')
    })
    await person.click(screen.getByRole('button', { name: 'Attach again' }))
    await waitFor(() => {
      expect(controls.terminalViews).toHaveLength(2)
    })
    await waitFor(() => {
      expect(screen.getAllByTestId('mobile-terminal-line').length).toBeGreaterThan(0)
    })
    expect(screen.getByRole('button', { name: 'Take control' })).not.toHaveFocus()
    act(() => {
      controls.terminalViews[1]?.end('The session ended again.')
    })
    screen.getByRole('button', { name: 'Attach again' }).focus()
    act(() => {
      controls.setConnected(true)
    })
    await waitFor(() => {
      expect(controls.terminalViews).toHaveLength(3)
    })
    await waitFor(() => {
      expect(screen.getAllByTestId('mobile-terminal-line').length).toBeGreaterThan(0)
    })
    expect(screen.getByRole('button', { name: 'Take control' })).toHaveFocus()
  })

  it('pays the focus owed once the mode button can take it, unless the person put it on another control first', async () => {
    // The bar that holds the mode button is hidden while a software keyboard is up: here, while
    // `hidden` holds, nothing in the bar is shown.
    let hidden = true
    Object.defineProperty(HTMLElement.prototype, 'checkVisibility', {
      configurable: true,
      value(this: HTMLElement) {
        return !(hidden && this.closest('.m-terminal-hud') !== null)
      }
    })
    try {
      for (const elsewhere of [false, true]) {
        hidden = true
        const { port, controls } = fakeHost()
        const person = await onTerminal(port)
        await waitFor(() => {
          expect(screen.getAllByTestId('mobile-terminal-line').length).toBeGreaterThan(0)
        })
        await takeControl(person, controls)
        programKeyboard()?.focus()
        act(() => {
          controls.terminalViews[0]?.loseControl()
        })
        await waitFor(() => {
          expect(programKeyboard()).toBeNull()
        })
        expect(screen.getByRole('button', { name: 'Take control' }), String(elsewhere)).not.toHaveFocus()
        if (elsewhere) {
          // Put on another control and let go again, with no commit between.
          const draft = screen.getByLabelText('Message this session')
          draft.focus()
          draft.blur()
        }
        hidden = false
        // A new screen commits with no change of the focus, and finds the mode button shown.
        act(() => {
          controls.terminalViews[0]?.show()
        })
        await act(async () => {
          await new Promise((resolve) => {
            setTimeout(resolve, 0)
          })
        })
        if (elsewhere) {
          expect(screen.getByRole('button', { name: 'Take control' }), 'settled').not.toHaveFocus()
        } else {
          expect(screen.getByRole('button', { name: 'Take control' }), 'paid').toHaveFocus()
        }
        cleanup()
      }
    } finally {
      Reflect.deleteProperty(HTMLElement.prototype, 'checkVisibility')
    }
  })

  it('owes no focus to a view the person left: coming back to the terminal leaves the focus where it is', async () => {
    const { port, controls } = fakeHost()
    const person = await onTerminal(port)
    await waitFor(() => {
      expect(screen.getAllByTestId('mobile-terminal-line').length).toBeGreaterThan(0)
    })
    await takeControl(person, controls)
    programKeyboard()?.focus()
    // A tap on a phone moves no focus to the button it taps: the view closes under the field.
    fireEvent.click(screen.getByRole('tab', { name: 'Conversation' }))
    await waitFor(() => {
      expect(programKeyboard()).toBeNull()
    })
    fireEvent.click(screen.getByRole('tab', { name: 'Terminal' }))
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Take control' })).toBeEnabled()
    })
    expect(screen.getByRole('button', { name: 'Take control' })).not.toHaveFocus()
  })

  it('leaves the focus alone when control ends after the person put it on a control outside the composer and let it go', async () => {
    const { port, controls } = fakeHost()
    const person = await onTerminal(port)
    await waitFor(() => {
      expect(screen.getAllByTestId('mobile-terminal-line').length).toBeGreaterThan(0)
    })
    await takeControl(person, controls)
    programKeyboard()?.focus()
    const elsewhere = screen.getByRole('tab', { name: 'Conversation' })
    elsewhere.focus()
    elsewhere.blur()
    expect(document.body).toHaveFocus()
    act(() => {
      controls.terminalViews[0]?.loseControl()
    })
    await waitFor(() => {
      expect(programKeyboard()).toBeNull()
    })
    await act(async () => {
      await new Promise((resolve) => {
        setTimeout(resolve, 0)
      })
    })
    expect(screen.getByRole('button', { name: 'Take control' })).not.toHaveFocus()
    expect(document.body).toHaveFocus()
  })

  it('moves on from the draft field with Control-Tab and back with Control-Shift-Tab, and leaves it Tab', async () => {
    const { port, controls } = fakeHost()
    controls.holdTerminalControl()
    const person = await onTerminal(port)
    await waitFor(() => {
      expect(screen.getAllByTestId('mobile-terminal-line').length).toBeGreaterThan(0)
    })
    await person.type(screen.getByLabelText('Message this session'), 'ls')
    const field = screen.getByLabelText('Message this session')
    for (const state of ['watching', 'taking'] as const) {
      if (state === 'taking') await person.click(screen.getByRole('button', { name: 'Take control' }))
      // The chord's default is prevented and the field moves the focus itself; a browser does
      // nothing with Control-Tab in a field.
      field.focus()
      expect(fireEvent.keyDown(field, { key: 'Tab', code: 'Tab', ctrlKey: true }), state).toBe(false)
      expect(screen.getByRole('button', { name: 'Send' }), state).toHaveFocus()
      field.focus()
      expect(
        fireEvent.keyDown(field, { key: 'Tab', code: 'Tab', ctrlKey: true, shiftKey: true }),
        state
      ).toBe(false)
      // Back past the terminal keys, which wait for control, to the status's More.
      expect(screen.getByRole('button', { name: 'More' }), state).toHaveFocus()
      // Tab and Shift-Tab are the platform's.
      field.focus()
      expect(fireEvent.keyDown(field, { key: 'Tab', code: 'Tab' }), state).toBe(true)
      expect(fireEvent.keyDown(field, { key: 'Tab', code: 'Tab', shiftKey: true }), state).toBe(true)
      expect(field, state).toHaveFocus()
    }
    expect(programInputs(controls)).toEqual([])
  })

  it('returns to view mode when control ends, says why, and moves focus from a key that can no longer be pressed', async () => {
    const { port, controls } = fakeHost()
    const person = await onTerminal(port)
    await waitFor(() => {
      expect(screen.getAllByTestId('mobile-terminal-line').length).toBeGreaterThan(0)
    })
    await takeControl(person, controls)
    const escape = screen.getByRole('button', { name: 'Escape' })
    escape.focus()
    expect(escape).toHaveFocus()
    act(() => {
      controls.terminalViews[0]?.loseControl()
    })
    expect(await screen.findByText(LOST_CONTROL)).toBeInTheDocument()
    expect(escape).toBeDisabled()
    const mode = screen.getByRole('button', { name: 'Take control' })
    expect(mode).toHaveFocus()
    expect(screen.getByRole('button', { name: 'Move the window up' })).toBeInTheDocument()
    // Asking again clears the words.
    await person.click(mode)
    await waitFor(() => {
      expect(screen.queryByText(LOST_CONTROL)).toBeNull()
    })
    // And from the program keyboard, which goes with control.
    await waitFor(() => {
      expect(programKeyboard()).not.toBeNull()
    })
    programKeyboard()?.focus()
    act(() => {
      controls.terminalViews[0]?.loseControl()
    })
    await waitFor(() => {
      expect(programKeyboard()).toBeNull()
    })
    expect(screen.getByRole('button', { name: 'Take control' })).toHaveFocus()
  })

  it('folds the composer to one line with Send beside it while the terminal shows, and leaves the picker to the conversation', async () => {
    const { port } = fakeHost()
    const person = userEvent.setup()
    render(
      <AppProvider port={port}>
        <OnSession sessionId={SESSION_MAIN} />
      </AppProvider>
    )
    const empty = 'Write something to send.'
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
    // The reason comes before the field's line, above it, where the composer yields first.
    expect(reason.compareDocumentPosition(field) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
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
      if (this.classList.contains('m-shell')) return DOMRect.fromRect({ x: 0, y: 0, width: 390, height: 800 })
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
    expect(status?.textContent).toContain(describeMode({ number: 0, state: 'watching', ended: null }, 'reaches'))

    await person.click(more)
    expect(screen.getByRole('button', { name: 'Less' })).toHaveAttribute('aria-expanded', 'true')
    expect(status).toHaveAttribute('data-expanded', 'true')
    await person.click(screen.getByRole('button', { name: 'Less' }))
    expect(screen.getByRole('button', { name: 'More' })).toHaveAttribute('aria-expanded', 'false')
  })

  it('keeps its controls in keyboard order: the mode, the moves, the status, the keys and the field, with Send after it', async () => {
    const { port, controls } = fakeHost()
    const person = await onTerminal(port)
    await waitFor(() => {
      expect(screen.getAllByTestId('mobile-terminal-line')).toHaveLength(8)
    })
    await person.type(screen.getByLabelText('Message this session'), 'ls')
    /** The names of the controls Tab reaches from `start`, in order. */
    const tabbing = async (start: HTMLElement): Promise<string[]> => {
      start.focus()
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
      return reached
    }
    // Watching: the mode, the moves, the status and the field, and Tab goes on from the field to
    // Send. The keys wait for control, out of the way.
    const watching = await tabbing(screen.getByRole('button', { name: 'Take control' }))
    const at = (reached: string[], name: string) => reached.indexOf(name)
    expect(at(watching, 'Move the window up')).toBe(0)
    expect(at(watching, 'More')).toBeGreaterThan(at(watching, 'Move the window up'))
    expect(at(watching, 'Escape')).toBe(-1)
    expect(at(watching, 'the field')).toBe(at(watching, 'More') + 1)
    expect(at(watching, 'Send')).toBe(at(watching, 'the field') + 1)

    // Controlling: the mode, the status, the keys and the program's keyboard in the field's place,
    // which keeps Tab for the program: the focus stays in it.
    await takeControl(person, controls)
    const controlling = await tabbing(screen.getByRole('button', { name: 'Look around' }))
    expect(at(controlling, 'More')).toBe(0)
    expect(at(controlling, 'Escape')).toBe(at(controlling, 'More') + 1)
    expect(at(controlling, 'the field')).toBeGreaterThan(at(controlling, 'Escape'))
    expect(controlling.slice(at(controlling, 'the field'))).toEqual(
      controlling.slice(at(controlling, 'the field')).map(() => 'the field')
    )
    expect(screen.queryByRole('button', { name: 'Send' })).toBeNull()
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

describe("the phone's composer on a short session (KR-REQ-13.19)", () => {
  it('folds to its line on a session too short for the whole of it and back, keeping the field, its focus and what was typed', async () => {
    const { port } = fakeHost()
    const person = userEvent.setup()
    // jsdom lays nothing out: a session 40 lines of the root text size high, then 20, then 40.
    const root = document.documentElement
    root.style.fontSize = '16px'
    let lines = 40
    const heights = vi.spyOn(Element.prototype, 'clientHeight', 'get').mockImplementation(function (
      this: Element
    ) {
      return this.classList.contains('m-session') ? lines * 16 : 0
    })
    const resized = (to: number) => {
      lines = to
      act(() => {
        window.dispatchEvent(new Event('resize'))
      })
    }
    try {
      render(
        <AppProvider port={port}>
          <OnSession sessionId={SESSION_MAIN} />
        </AppProvider>
      )
      const field = screen.getByLabelText('Message this session')
      const send = () => screen.getByRole('button', { name: 'Send' })
      const line = () => send().closest('.m-composer-line')
      // The whole composer: Send under the pickers, and words for why an empty draft waits.
      expect(line()).toBeNull()
      expect(screen.getByText('Write something to send.')).toBeInTheDocument()

      await person.click(field)
      await person.type(field, 'hel')
      resized(20)
      // Its line: Send beside the field, which needs no words while the draft is empty, the pickers
      // still under it, and the same field, still focused, still holding what was typed.
      await waitFor(() => {
        expect(line()).not.toBeNull()
      })
      expect(document.querySelector('.m-session')).toHaveAttribute('data-composer', 'line')
      expect(screen.getByLabelText('Message this session')).toBe(field)
      expect(line()).toContainElement(field)
      expect(field).toHaveFocus()
      expect(screen.getByRole('group', { name: 'Add an attachment' })).toBeInTheDocument()
      await person.type(field, 'lo')
      expect(field).toHaveValue('hello')
      await person.clear(field)
      expect(screen.queryByText('Write something to send.')).toBeNull()
      expect(send()).toBeDisabled()

      resized(40)
      await waitFor(() => {
        expect(line()).toBeNull()
      })
      expect(document.querySelector('.m-session')).toHaveAttribute('data-composer', 'whole')
      expect(screen.getByLabelText('Message this session')).toBe(field)
      expect(field).toHaveFocus()
      expect(screen.getByText('Write something to send.')).toBeInTheDocument()
    } finally {
      heights.mockRestore()
      root.style.removeProperty('font-size')
    }
  })

  it('keeps the focus on Send as it moves beside the field and back', async () => {
    const { port } = fakeHost()
    const person = userEvent.setup()
    const root = document.documentElement
    root.style.fontSize = '16px'
    let lines = 40
    const heights = vi.spyOn(Element.prototype, 'clientHeight', 'get').mockImplementation(function (
      this: Element
    ) {
      return this.classList.contains('m-session') ? lines * 16 : 0
    })
    const resized = (to: number) => {
      lines = to
      act(() => {
        window.dispatchEvent(new Event('resize'))
      })
    }
    try {
      render(
        <AppProvider port={port}>
          <OnSession sessionId={SESSION_MAIN} />
        </AppProvider>
      )
      await person.type(screen.getByLabelText('Message this session'), 'hello')
      const before = screen.getByRole('button', { name: 'Send' })
      act(() => {
        before.focus()
      })
      resized(20)
      await waitFor(() => {
        expect(screen.getByRole('button', { name: 'Send' }).closest('.m-composer-line')).not.toBeNull()
      })
      expect(screen.getByRole('button', { name: 'Send' })).toHaveFocus()
      resized(40)
      await waitFor(() => {
        expect(screen.getByRole('button', { name: 'Send' }).closest('.m-composer-line')).toBeNull()
      })
      expect(screen.getByRole('button', { name: 'Send' })).toHaveFocus()
    } finally {
      heights.mockRestore()
      root.style.removeProperty('font-size')
    }
  })
})
