/**
 * The phone's session view shows only what it read for the session on screen.
 *
 * Every read's answer is kept with the session it was read for and shown only for that session,
 * from the first render after a change of session, and a read made for a session the view has left
 * is never shown. Before its first answer the conversation says it is reading, and a refused read
 * says so rather than calling the conversation empty.
 */

import { Profiler, type ReactNode } from 'react'
import { describe, expect, it } from 'vitest'
import { act, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import type { DocumentNode } from '@kalareach/plugin-sdk'

import { AppProvider } from '../../src/app/state'
import { fakeHost, terminalScreen, type HeldReads } from '../../src/host/fake'
import { MobileSession } from '../../src/mobile/views/MobileSession'
import { useLifecycle } from '../../src/mobile/useLifecycle'

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
