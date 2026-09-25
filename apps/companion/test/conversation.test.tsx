/**
 * The conversation listens, then reads.
 *
 * The document is read once the host-event listener is registered, and the nodes the stream
 * delivers while that read is on its way are held until it answers. A node can then neither fall
 * between the read and the listener nor land ahead of the document it follows, and a refusal to
 * read is shown for what it is.
 */

import { describe, expect, it } from 'vitest'
import { act, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import type { DocumentNode } from '@kalareach/plugin-sdk'

import { App } from '../src/App'
import { AppProvider } from '../src/app/state'
import { fakeHost, type HeldReads } from '../src/host/fake'
import type { HostEvent, HostPort } from '../src/host/port'
import { animationFrame } from '../src/model/frame'

const SESSION_MAIN = '8a7b6c50-22bb-4c3d-8e4f-000000000101'

/** The document the scripted host starts with, in its presentation order. */
const DOCUMENT = ['n-1', 'n-2', 'n-3', 'n-4', 'n-5', 'n-6']

/** The application on the main session's conversation, against a host the test has prepared. */
function openConversation(port: HostPort): void {
  render(
    <AppProvider
      port={port}
      initialPlace={{ view: 'session', sessionId: SESSION_MAIN, pane: 'semantic' }}
    >
      <App />
    </AppProvider>
  )
}

/** The nodes the document shows, in the order it shows them. */
function shown(): string[] {
  return [
    ...document.querySelectorAll<HTMLElement>('[data-testid="conversation-scroll"] [data-node-id]')
  ].map((node) => node.dataset.nodeId ?? '')
}

/** What one shown node says. */
function said(id: string): string {
  return (
    document.querySelector(`[data-testid="conversation-scroll"] [data-node-id="${id}"]`)
      ?.textContent ?? ''
  )
}

function message(id: string, revision: string, text: string): DocumentNode {
  return { id, revision, body: { kind: 'message', author: 'agent', text } }
}

/** One node on the main session's stream, as the host publishes it. */
function streamed(node: DocumentNode, sequence: string): HostEvent {
  return { stream_id: `semantic:${SESSION_MAIN}`, sequence, body: { kind: 'node', node } }
}

/**
 * Lets the frame the stream's batch is published on pass. A node the view applied as it arrived is
 * on the page after this; a node it is holding is not.
 */
async function nextFrame(): Promise<void> {
  await act(async () => {
    await new Promise<void>((resolve) => {
      animationFrame(resolve)
    })
  })
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

/** Waits until `count` reads of a kind have been made. */
async function made(held: HeldReads, count: number): Promise<void> {
  await waitFor(() => {
    expect(held.count).toBe(count)
  })
}

const REFUSED = {
  code: 'RESOURCE_UNAVAILABLE',
  message: 'The host did not give the document.',
  user_action: 'retry'
}

describe('the conversation reads its document once it is listening (KR-REQ-13.02)', () => {
  it('shows a node the host added while its listener registered, after the document', async () => {
    const { port, controls } = fakeHost()
    const complete = controls.holdRegistrations()
    openConversation(port)

    act(() => {
      controls.appendNode(message('n-7', '1', 'Added while the view registered.'))
    })
    await act(async () => {
      complete()
      await Promise.resolve()
    })

    await waitFor(() => {
      expect(shown()).toEqual([...DOCUMENT, 'n-7'])
    })
  })

  it('puts a node streamed while the document is read after the document', async () => {
    const { port, controls } = fakeHost()
    const held = controls.hold('agentSnapshot')
    openConversation(port)
    await waitFor(() => {
      expect(held.count).toBe(1)
    })

    act(() => {
      controls.appendNode(message('n-7', '1', 'Streamed while the document was read.'))
    })
    await nextFrame()
    await act(async () => {
      held.release()
      await Promise.resolve()
    })

    await waitFor(() => {
      expect(shown()).toEqual([...DOCUMENT, 'n-7'])
    })
  })

  it('takes a streamed node in place of the document’s copy only when it is newer', async () => {
    const { port, controls } = fakeHost()
    const held = controls.hold('agentSnapshot')
    openConversation(port)
    await waitFor(() => {
      expect(held.count).toBe(1)
    })

    // The document holds n-3 at revision 2 and n-2 at revision 1.
    act(() => {
      controls.emit(streamed(message('n-3', '3', 'The newer n-3.'), '7'))
      controls.emit(streamed(message('n-2', '0', 'An older n-2.'), '8'))
    })
    await nextFrame()
    await act(async () => {
      held.release()
      await Promise.resolve()
    })

    await waitFor(() => {
      expect(shown()).toEqual(DOCUMENT)
    })
    expect(said('n-3')).toContain('The newer n-3.')
    expect(said('n-2')).not.toContain('An older n-2.')
    expect(said('n-2')).toContain('The test waits on a')
  })

  it('shows the host’s refusal to read the document', async () => {
    const { port, controls } = fakeHost()
    controls.setConnected(false)
    openConversation(port)

    const refusal = await screen.findByTestId('conversation-unread')
    expect(refusal.textContent).toContain('This conversation could not be read')
    expect(refusal.textContent).toContain('This host cannot be contacted right now.')
    expect(shown()).toEqual([])
  })

  it('takes a refusal made before the port returned a promise as the answer', async () => {
    const { port } = fakeHost()
    openConversation({
      ...port,
      agentSnapshot: () => {
        // eslint-disable-next-line @typescript-eslint/only-throw-error -- the refusal's own shape
        throw {
          code: 'RESOURCE_UNAVAILABLE',
          message: 'The host refused before it answered.',
          user_action: 'retry'
        }
      }
    })

    const refusal = await screen.findByTestId('conversation-unread')
    expect(within(refusal).getByText('The host refused before it answered.')).toBeInTheDocument()
  })

  it('shows a refusal that came with no words as a refusal', async () => {
    const { port } = fakeHost()
    openConversation({
      ...port,
      agentSnapshot: () =>
        Promise.reject({ code: 'RESOURCE_UNAVAILABLE', message: '', user_action: 'retry' })
    })

    const refusal = await screen.findByTestId('conversation-unread')
    expect(refusal.textContent).toContain('This conversation could not be read')
    expect(refusal.textContent).toContain('Something went wrong.')
  })

  it('reads the document again once the host is back, and the refusal goes', async () => {
    const { port, controls } = fakeHost()
    controls.setConnected(false)
    openConversation(port)
    await screen.findByTestId('conversation-unread')

    act(() => {
      controls.setConnected(true)
    })

    await waitFor(() => {
      expect(shown()).toEqual(DOCUMENT)
    })
    expect(screen.queryByTestId('conversation-unread')).toBeNull()
  })

  it('installs only the newest of two reads, with every node streamed across both', async () => {
    const { port, controls } = fakeHost()
    const held = controls.hold('agentSnapshot')
    openConversation(port)
    await made(held, 1)

    // A connection change that says the host is there reads the document again.
    act(() => {
      controls.setConnected(true)
    })
    await made(held, 2)
    act(() => {
      controls.appendNode(message('n-7', '1', 'Streamed while both reads were out.'))
    })
    await nextFrame()

    await answer(held, 0)
    expect(shown()).toEqual([])
    await answer(held, 1)
    expect(shown()).toEqual([...DOCUMENT, 'n-7'])
  })

  it('keeps a node that arrived before a later read ahead of one that arrived during it', async () => {
    const { port, controls } = fakeHost()
    let reads = 0
    openConversation({
      ...port,
      agentSnapshot: (params) => {
        reads += 1
        return reads === 1 ? port.agentSnapshot(params) : Promise.reject(REFUSED)
      }
    })
    await waitFor(() => {
      expect(shown()).toEqual(DOCUMENT)
    })

    // n-7 is waiting for its frame when the host is heard to be back; the read that starts then is
    // refused, and n-8 arrives while it is on its way.
    act(() => {
      controls.appendNode(message('n-7', '1', 'Before the second read.'))
      controls.setConnected(true)
      controls.emit(streamed(message('n-8', '1', 'During the second read.'), '9'))
    })
    await screen.findByTestId('conversation-unread')
    await nextFrame()
    expect(shown()).toEqual([...DOCUMENT, 'n-7', 'n-8'])
  })

  it('says why when it cannot follow the stream, and reads nothing', async () => {
    const { port } = fakeHost()
    openConversation({
      ...port,
      subscribe: () =>
        Promise.reject({
          code: 'INTERNAL',
          message: 'The event stream could not be opened.',
          user_action: 'retry'
        })
    })

    const refusal = await screen.findByTestId('conversation-unread')
    expect(within(refusal).getByText('The event stream could not be opened.')).toBeInTheDocument()
    expect(shown()).toEqual([])
  })

  it('shows no refusal from before on a return to a session, until it has read it again', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    let refusing = true
    render(
      <AppProvider
        port={{
          ...port,
          agentSnapshot: (params) =>
            refusing && (params as { session_id?: string }).session_id === SESSION_MAIN
              ? Promise.reject(REFUSED)
              : port.agentSnapshot(params)
        }}
        initialPlace={{ view: 'sessions' }}
      >
        <App />
      </AppProvider>
    )
    await person.click(await screen.findByTestId('session-row-2'))
    await screen.findByText('Session 2 · Working')
    await person.click(screen.getByRole('button', { name: 'Sessions' }))
    await person.click(await screen.findByTestId('session-row-1'))
    await screen.findByTestId('conversation-unread')

    refusing = false
    const held = controls.hold('agentSnapshot')
    await person.click(screen.getByRole('tab', { name: 'Session 02' }))
    await made(held, 1)
    await person.click(screen.getByRole('tab', { name: 'Session 01' }))
    await made(held, 2)
    expect(screen.queryByTestId('conversation-unread')).toBeNull()

    await answer(held, 1)
    expect(shown()).toEqual(DOCUMENT)
    expect(screen.queryByTestId('conversation-unread')).toBeNull()
  })

  it('shows the document it read when nothing streamed meanwhile', async () => {
    const { port } = fakeHost()
    openConversation(port)

    await waitFor(() => {
      expect(shown()).toEqual(DOCUMENT)
    })
    expect(screen.queryByTestId('conversation-unread')).toBeNull()
  })
})
