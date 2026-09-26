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
    // 336 pixels wide in a pane 420 high, 8 pixels of padding around the grid, and cells of 8 by 16
    // pixels at the unscaled size, which grow with the zoom as the font does.
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
      return this.classList.contains('m-pane') ? 420 : 0
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
