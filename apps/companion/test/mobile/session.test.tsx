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
import { fakeHost, type HeldReads } from '../../src/host/fake'
import { MobileSession } from '../../src/mobile/views/MobileSession'
import { useLifecycle } from '../../src/mobile/useLifecycle'
import { terminalAttachment } from '../../src/terminal/modes'

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
    controls.presentAttachment(terminalAttachment(SESSION_MAIN), 'viewport', 'size_mismatch')
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

    // Session 2's reads are held, so nothing of it is shown either.
    controls.hold('terminalProjection')
    controls.hold('eventsSnapshot')
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
