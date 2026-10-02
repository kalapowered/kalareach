/**
 * The conversation reads the agent's history from its worker, and listens for what packages show.
 *
 * The history is an ordered log with a number on every entry, and the host announces nothing when
 * an entry is added, so the view reads it again while it is shown, each time from the entry after
 * the last one it holds: while an agent runs, nothing falls between two reads and nothing is read
 * twice, and an agent that ended before its last entries were read is said to have. One read is on
 * its way at a time. What a package shows arrives on the host's event stream, for the session the
 * stream names. A refusal to read, and a stream that cannot be followed, are each shown for what
 * they are, and what the host's filter withheld is counted once however often the view reads.
 * What the person writes goes to the conversation they wrote it for, or nowhere until they choose.
 */

import { describe, expect, it } from 'vitest'
import { act, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import type { DocumentNode } from '@kalareach/plugin-sdk'
import type { AgentSnapshotParams } from '@kalareach/protocol'

import { App } from '../src/App'
import { AppProvider } from '../src/app/state'
import { fakeHost, type HeldReads } from '../src/host/fake'
import type { HostEvent, HostPort } from '../src/host/port'
import { animationFrame } from '../src/model/frame'

const SESSION_MAIN = '8a7b6c50-22bb-4c3d-8e4f-000000000101'
const SESSION_BUILD = '8a7b6c50-22bb-4c3d-8e4f-000000000102'
const INSTANCE_MAIN = 'a1a1a1a1-0000-4000-8000-000000000001'

/** The identity the conversation gives the main agent's entry `node`. */
const entry = (node: number) => `${INSTANCE_MAIN}:${node}`

/** The main agent's history as the scripted host starts it. */
const HISTORY = [1, 2, 3, 4, 5].map(entry)

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

/** The items the conversation shows, in the order it shows them. */
function shown(): string[] {
  return [
    ...document.querySelectorAll<HTMLElement>('[data-testid="conversation-scroll"] [data-node-id]')
  ].map((node) => node.dataset.nodeId ?? '')
}

/** What one shown item says. */
function said(id: string): string {
  return (
    document.querySelector(`[data-testid="conversation-scroll"] [data-node-id="${id}"]`)
      ?.textContent ?? ''
  )
}

function message(id: string, revision: string, text: string): DocumentNode {
  return { id, revision, body: { kind: 'message', author: 'agent', text } }
}

/** One node on a session's presentation stream, as the host publishes it. */
function streamed(node: DocumentNode, sequence: string, sessionId = SESSION_MAIN): HostEvent {
  return { stream_id: `semantic:${sessionId}`, sequence, body: { kind: 'node', node } }
}

/** Lets the frame a streamed batch is published on pass. */
async function nextFrame(): Promise<void> {
  await act(async () => {
    await new Promise<void>((resolve) => {
      animationFrame(resolve)
    })
  })
}

/** The page is shown again, as a window brought back from the Dock is: the view reads at once. */
async function shownAgain(): Promise<void> {
  await act(async () => {
    document.dispatchEvent(new Event('visibilitychange'))
    await Promise.resolve()
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
  message: 'The host did not give the history.',
  user_action: 'retry'
}

describe('the conversation reads the agent from its worker (KR-REQ-13.02, 11.03)', () => {
  it("shows the agent's history in the order its worker gives it", async () => {
    const { port } = fakeHost()
    openConversation(port)

    await waitFor(() => {
      expect(shown()).toEqual(HISTORY)
    })
    expect(said(entry(2))).toContain('Find why the reconnect test is flaky.')
    expect(screen.queryByTestId('conversation-unread')).toBeNull()
  })

  it('reads only what follows the last entry it holds', async () => {
    const { port, controls } = fakeHost()
    const froms: (string | null)[] = []
    openConversation({
      ...port,
      agentSnapshot: (params) => {
        froms.push(params.from_node)
        return port.agentSnapshot(params)
      }
    })
    await waitFor(() => {
      expect(shown()).toEqual(HISTORY)
    })

    controls.records.appendEntry(SESSION_MAIN, 'message', 'Added after the first read.')
    await shownAgain()

    await waitFor(() => {
      expect(shown()).toEqual([...HISTORY, entry(6)])
    })
    expect(said(entry(6))).toContain('Added after the first read.')
    // The first read starts at the beginning; every later one after the newest entry it holds.
    expect(froms[0]).toBeNull()
    expect(froms).toContain('6')
    expect(froms.slice(1).every((from) => from !== null)).toBe(true)
  })

  it('shows the host’s refusal to read the conversation', async () => {
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

  it('reads again once the host is back, and the refusal goes', async () => {
    const { port, controls } = fakeHost()
    controls.setConnected(false)
    openConversation(port)
    await screen.findByTestId('conversation-unread')

    act(() => {
      controls.setConnected(true)
    })

    await waitFor(() => {
      expect(shown()).toEqual(HISTORY)
    })
    expect(screen.queryByTestId('conversation-unread')).toBeNull()
  })

  it('has one read on its way at a time, and a read asked for meanwhile follows it', async () => {
    const { port, controls } = fakeHost()
    const held = controls.hold('agentSnapshot')
    openConversation(port)
    await made(held, 1)

    // A connection change that says the host is there asks for a read while one is on its way.
    act(() => {
      controls.setConnected(true)
    })
    await act(async () => {
      await new Promise((resolve) => {
        setTimeout(resolve, 20)
      })
    })
    expect(held.count).toBe(1)

    // The read that found the history reads on from after its last entry, and only then is it
    // one read done.
    await answer(held, 0)
    await made(held, 2)
    await answer(held, 1)
    expect(shown()).toEqual(HISTORY)
    await made(held, 3)
    held.release()
  })

  it('says why when it cannot follow the stream, and still shows the history', async () => {
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

    const refusal = await screen.findByTestId('conversation-unfollowed')
    expect(refusal.textContent).toContain('The event stream could not be opened.')
    await waitFor(() => {
      expect(shown()).toEqual(HISTORY)
    })
    expect(screen.queryByTestId('conversation-unread')).toBeNull()
  })

  it('shows no refusal from before on a return to a session, until it has read it again', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    let refusing = true
    render(
      <AppProvider
        port={{
          ...port,
          agentSnapshot: (params: AgentSnapshotParams) =>
            refusing && params.subject.session_id === SESSION_MAIN
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

    held.release()
    await waitFor(() => {
      expect(shown()).toEqual(HISTORY)
    })
    expect(screen.queryByTestId('conversation-unread')).toBeNull()
  })
})

describe('what the conversation says it does not show (KR-REQ-13.15, 25.25)', () => {
  it('counts what the host withheld once, however often it reads', async () => {
    const { port, controls } = fakeHost()
    controls.records.withhold(SESSION_MAIN, 2)
    openConversation(port)

    await waitFor(() => {
      expect(shown()).toEqual(HISTORY.slice(2))
    })
    expect(screen.getByTestId('withheld').textContent).toContain(
      'At least 2 entries are outside what this device may see.'
    )

    await shownAgain()
    controls.records.appendEntry(SESSION_MAIN, 'message', 'Seen by this device.')
    await shownAgain()
    await waitFor(() => {
      expect(shown()).toEqual([...HISTORY.slice(2), entry(6)])
    })
    await shownAgain()
    expect(screen.getByTestId('withheld').textContent).toContain(
      'At least 2 entries are outside what this device may see.'
    )
  })

  it('counts an entry withheld after a shown one once, however often it reads', async () => {
    const { port, controls } = fakeHost()
    // The filter withholds the newest entry, and keeps doing so as the history grows past it.
    controls.records.withholdEntry(SESSION_MAIN, 5)
    openConversation(port)

    await waitFor(() => {
      expect(shown()).toEqual(HISTORY.slice(0, 4))
    })
    expect(screen.getByTestId('withheld').textContent).toContain(
      'At least 1 entry is outside what this device may see.'
    )
    await shownAgain()
    controls.records.appendEntry(SESSION_MAIN, 'message', 'After the withheld one.')
    await shownAgain()
    await waitFor(() => {
      expect(shown()).toEqual([...HISTORY.slice(0, 4), entry(6)])
    })
    await shownAgain()
    expect(screen.getByTestId('withheld').textContent).toContain(
      'At least 1 entry is outside what this device may see.'
    )
  })

  it('says so when an agent it was reading ended before its last entries were read', async () => {
    const { port, controls } = fakeHost()
    openConversation(port)
    await waitFor(() => {
      expect(shown()).toEqual(HISTORY)
    })

    controls.records.appendEntry(SESSION_MAIN, 'message', 'Written just before it quit.')
    const next = controls.records.restartAgent(SESSION_MAIN)
    await shownAgain()

    await waitFor(() => {
      expect(shown()).toEqual([...HISTORY, `${next}:1`])
    })
    expect(screen.getByTestId('unfinished').textContent).toContain(
      'Anything it wrote after this device last read it is not shown.'
    )
  })

  it('says how much of an entry was not carried', async () => {
    const { port, controls } = fakeHost()
    controls.records.appendEntry(SESSION_MAIN, 'message', 'The start of a long answer', 5_000)
    openConversation(port)

    await waitFor(() => {
      expect(shown()).toEqual([...HISTORY, entry(6)])
    })
    const cut = within(
      document.querySelector(`[data-node-id="${entry(6)}"]`) as HTMLElement
    ).getByTestId('entry-cut')
    expect(cut.textContent).toContain('5,000 more bytes of this entry were not carried.')
  })

  it('says so when entries it had not read were no longer kept', async () => {
    const { port, controls } = fakeHost()
    openConversation(port)
    await waitFor(() => {
      expect(shown()).toEqual(HISTORY)
    })

    for (const text of ['six', 'seven', 'eight']) {
      controls.records.appendEntry(SESSION_MAIN, 'message', text)
    }
    controls.records.forget(SESSION_MAIN, 7)
    await shownAgain()

    await waitFor(() => {
      expect(shown()).toEqual([...HISTORY, entry(8)])
    })
    expect(screen.getByTestId('history-notes').textContent).toContain(
      'Some of this agent’s earlier entries were no longer kept when this device read them.'
    )
  })
})

describe('what the person writes goes where they wrote it (KR-REQ-13.12)', () => {
  it('asks before sending a draft to a conversation that moved on while it was written', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    const sent: string[] = []
    openConversation({
      ...port,
      composerSubmit: (params) => {
        sent.push(params.target.binding_revision)
        return port.composerSubmit(params)
      }
    })
    await waitFor(() => {
      expect(shown()).toEqual(HISTORY)
    })
    await person.type(screen.getByTestId('composer-input'), 'Keep the timer')

    // The agent moves to another conversation while the draft is on screen.
    controls.records.moveBinding(SESSION_MAIN)
    await shownAgain()
    await waitFor(() => {
      expect(screen.getByTestId('composer-reason')).toHaveTextContent(
        'The conversation changed since this was written.'
      )
    })
    expect(screen.getByTestId('composer-send')).toBeDisabled()
    expect(screen.getByTestId('composer-input')).toHaveValue('Keep the timer')

    // Only the person sends it on.
    await person.click(screen.getByTestId('composer-retarget'))
    expect(screen.getByTestId('composer-send')).toBeEnabled()
    await person.click(screen.getByTestId('composer-send'))
    await waitFor(() => {
      expect(sent).toEqual(['5'])
    })
  })

  it('keeps a draft written before the agent was read to the first conversation it learns', async () => {
    const person = userEvent.setup()
    const { port, controls } = fakeHost()
    const held = controls.hold('agentSnapshot')
    openConversation(port)
    await made(held, 1)
    // Written while the agent is still being read.
    await person.type(screen.getByTestId('composer-input'), 'Written early')
    held.release()
    await waitFor(() => {
      expect(shown()).toEqual(HISTORY)
    })

    // The conversation moves on without another keystroke: the draft does not follow it.
    controls.records.moveBinding(SESSION_MAIN)
    await shownAgain()
    await waitFor(() => {
      expect(screen.getByTestId('composer-reason')).toHaveTextContent(
        'The conversation changed since this was written.'
      )
    })
    expect(screen.getByTestId('composer-send')).toBeDisabled()
  })

  it('sends what was written at the binding revision it was written at', async () => {
    const person = userEvent.setup()
    const { port } = fakeHost()
    const sent: string[] = []
    openConversation({
      ...port,
      composerSubmit: (params) => {
        sent.push(params.target.binding_revision)
        return port.composerSubmit(params)
      }
    })
    await waitFor(() => {
      expect(shown()).toEqual(HISTORY)
    })
    await person.type(screen.getByTestId('composer-input'), 'Run the tests')
    await person.click(screen.getByTestId('composer-send'))
    await waitFor(() => {
      expect(sent).toEqual(['4'])
    })
  })
})

describe('what packages show arrives on the stream (KR-REQ-11.48)', () => {
  it('shows a node streamed for this session after what it holds, and none for another', async () => {
    const { port, controls } = fakeHost()
    openConversation(port)
    await waitFor(() => {
      expect(shown()).toEqual(HISTORY)
    })

    act(() => {
      controls.appendNode(message('n-7', '1', 'Streamed for this session.'))
      controls.emit(streamed(message('n-8', '1', 'Streamed for another.'), '9', SESSION_BUILD))
    })
    await nextFrame()

    expect(shown()).toEqual([...HISTORY, 'n-7'])
  })

  it('takes a streamed node in place of the copy it holds only when it is newer', async () => {
    const { port, controls } = fakeHost()
    openConversation(port)
    await waitFor(() => {
      expect(shown()).toEqual(HISTORY)
    })

    act(() => {
      controls.emit(streamed(message('n-7', '2', 'The newer n-7.'), '7'))
      controls.emit(streamed(message('n-7', '1', 'An older n-7.'), '8'))
    })
    await nextFrame()

    expect(shown()).toEqual([...HISTORY, 'n-7'])
    expect(said('n-7')).toContain('The newer n-7.')
  })
})

describe('the conversation names each kind of entry in words (KR-REQ-13.19)', () => {
  it('names a kind it does not know by a generic label and keeps the identifier as data', async () => {
    const { port, controls } = fakeHost()
    openConversation(port)
    await waitFor(() => {
      expect(shown()).toEqual(HISTORY)
    })
    controls.records.appendEntry(SESSION_MAIN, 'tool.failed', 'cargo test exited 101')
    controls.records.appendEntry(SESSION_MAIN, 'plan.revised', 'Two steps were added.')
    await shownAgain()
    await waitFor(() => {
      expect(shown()).toEqual([...HISTORY, entry(6), entry(7)])
    })

    expect(said(entry(4))).toContain('Tool finished')
    expect(said(entry(6))).toContain('Tool failed')
    expect(said(entry(7))).toContain('Update from the agent')
    expect(said(entry(7))).toContain('Two steps were added.')
    // What a person reads has no identifier in it; the identifier is data on the entry.
    const scroll = screen.getByTestId('conversation-scroll').textContent ?? ''
    expect(scroll).not.toMatch(/plan\.revised|tool\.failed|tool\.finished/)
    expect(
      document.querySelector(`[data-node-id="${entry(7)}"]`)?.getAttribute('data-kind')
    ).toBe('plan.revised')
  })
})
