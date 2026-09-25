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

import type { DocumentNode } from '@kalareach/plugin-sdk'

import { App } from '../src/App'
import { AppProvider } from '../src/app/state'
import { fakeHost } from '../src/host/fake'
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

  it('shows the document it read when nothing streamed meanwhile', async () => {
    const { port } = fakeHost()
    openConversation(port)

    await waitFor(() => {
      expect(shown()).toEqual(DOCUMENT)
    })
    expect(screen.queryByTestId('conversation-unread')).toBeNull()
  })
})
