/**
 * A prompt whose outcome the host has not confirmed, on the desktop and on the phone.
 *
 * Section 9 lets an unknown receipt become applied or refused later, by reconciliation, and never
 * redispatches it. So nothing here sends a second time while an outcome is unknown, a prompt the
 * host has only accepted is not yet a prompt it took, and the interface asks the host what became
 * of an action rather than waiting for an event that may never come.
 */

import { act, cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it } from 'vitest'

import type { AgentMutationResult, Receipt } from '@kalareach/protocol'

import { App } from '../src/App'
import { AppProvider } from '../src/app/state'
import { fakeHost } from '../src/host/fake'
import { FakeDraftStore } from '../src/host/fake-drafts'
import type { HostPort, Settled } from '../src/host/port'
import { MobileApp } from '../src/mobile/MobileApp'

const SESSION_MAIN = '8a7b6c50-22bb-4c3d-8e4f-000000000101'
const ACTION = '00000000-0000-4000-8000-00000000abcd'

afterEach(cleanup)

/** A receipt of a prompt's action, at the state the host last recorded. */
function receiptAt(state: Receipt['state'], action = ACTION): Receipt {
  return {
    action_id: action,
    actor_id: 'owner:local',
    error: null,
    method: 'agent.prompt.submit',
    method_version: 1,
    payload_digest: '0'.repeat(64),
    reason: null,
    revision: '1',
    state,
    updated_at_ms: '0',
    accepted_deadline_ms: null
  }
}

/** The answer of a host that never confirmed what became of the request: only its identity. */
const UNCONFIRMED: Settled<AgentMutationResult> = { receipt: null, value: null, action_id: ACTION }

/** The answer of a host that has the request and is not done with it. */
const WITH_THE_HOST: Settled<AgentMutationResult> = { receipt: receiptAt('dispatching'), value: null, action_id: ACTION }

/** What the host recorded of the actions: one state for all, or a state for each action named. */
interface Recorded {
  state: Receipt['state']
  byAction?: Record<string, Receipt['state']>
}

/**
 * A port whose prompts are answered with `answer` (or, for the one asked for the nth time, with
 * what a function of n says), and whose record of an action is `recorded`.
 */
function answering(
  port: HostPort,
  answer: Settled<AgentMutationResult> | ((attempt: number) => Settled<AgentMutationResult>),
  recorded: Recorded,
  reads: string[] = [],
  sent: unknown[] = []
): HostPort {
  return {
    ...port,
    composerSubmit: (params) => {
      sent.push(params)
      return Promise.resolve(typeof answer === 'function' ? answer(sent.length) : answer)
    },
    actionRead: (params) => {
      reads.push(params.action_id)
      const state = recorded.byAction?.[params.action_id] ?? recorded.state
      return Promise.resolve({ receipt: receiptAt(state, params.action_id), result: null })
    }
  }
}

/** A storage that behaves like the device's own, so a test can restart the application over it. */
function fakeStorage(): Storage {
  const values = new Map<string, string>()
  return {
    get length() {
      return values.size
    },
    clear: () => {
      values.clear()
    },
    getItem: (key: string) => values.get(key) ?? null,
    key: (index: number) => [...values.keys()][index] ?? null,
    removeItem: (key: string) => {
      values.delete(key)
    },
    setItem: (key: string, value: string) => {
      values.set(key, value)
    }
  }
}

/** Lets the answers that are on their way reach the page: a macrotask passes after every microtask. */
async function flush(): Promise<void> {
  await act(async () => {
    await new Promise<void>((resolve) => setTimeout(resolve, 0))
  })
}

describe('on the desktop', () => {
  /** The desktop's conversation over a device's drafts, with the person's text sent once. */
  async function sentOnce(
    answer: Settled<AgentMutationResult> | ((attempt: number) => Settled<AgentMutationResult>),
    recorded: Recorded,
    reads: string[] = [],
    sent: unknown[] = []
  ) {
    const device = new FakeDraftStore()
    const host = fakeHost({ drafts: device })
    render(
      <AppProvider
        port={answering(host.port, answer, recorded, reads, sent)}
        initialPlace={{ view: 'session', sessionId: SESSION_MAIN, pane: 'semantic' }}
      >
        <App />
      </AppProvider>
    )
    const person = userEvent.setup()
    await person.type(await screen.findByTestId('composer-input'), 'run the migration')
    await waitFor(() => {
      expect(screen.getByTestId('composer-send')).toBeEnabled()
    })
    await person.click(screen.getByTestId('composer-send'))
    return { ...host, device, person }
  }

  it('will not send again while an action has no confirmed outcome, and sends once it has one', async () => {
    // The host's own record is unknown too, so only a late receipt can settle it.
    const recorded = { state: 'unknown' as Receipt['state'] }
    const sent: unknown[] = []
    const { controls, person } = await sentOnce(UNCONFIRMED, recorded, [], sent)

    // The text came back to the composer, as a prompt of unknown outcome gives it back.
    await waitFor(() => {
      expect(screen.getByTestId('composer-reason')).toHaveTextContent(/no confirmed outcome yet/)
    })
    expect(screen.getByTestId('composer-reason')).toHaveTextContent(/Sending again could run it twice/)
    expect(screen.getByTestId('composer-send')).toBeDisabled()
    expect(screen.getByTestId('composer-queue')).toBeDisabled()
    expect(sent).toHaveLength(1)

    // A late receipt says it was applied: the person can write the next thing.
    act(() => {
      controls.emit({
        stream_id: `receipts:${SESSION_MAIN}`,
        sequence: '1',
        body: { kind: 'receipt', receipt: receiptAt('applied') }
      })
    })
    await person.clear(screen.getByTestId('composer-input'))
    await person.type(screen.getByTestId('composer-input'), 'and then the next')
    await waitFor(() => {
      expect(screen.getByTestId('composer-send')).toBeEnabled()
    })
  })

  it('asks the host what became of an action whose outcome it never confirmed', async () => {
    // The host reconciled it already; no event tells the page, so only a read can.
    const recorded = { state: 'applied' as Receipt['state'] }
    const reads: string[] = []
    const { person } = await sentOnce(UNCONFIRMED, recorded, reads)

    await waitFor(
      () => {
        expect(screen.getByTestId('composer-reason')).not.toHaveTextContent(/no confirmed outcome/)
      },
      { timeout: 3_000 }
    )
    expect(new Set(reads)).toEqual(new Set([ACTION]))
    await person.clear(screen.getByTestId('composer-input'))
    await person.type(screen.getByTestId('composer-input'), 'the next thing')
    await waitFor(() => {
      expect(screen.getByTestId('composer-send')).toBeEnabled()
    })
  })

  it('keeps holding an action the host itself still records as unknown', async () => {
    const recorded = { state: 'unknown' as Receipt['state'] }
    const reads: string[] = []
    await sentOnce(UNCONFIRMED, recorded, reads)
    await waitFor(
      () => {
        expect(reads.length).toBeGreaterThan(0)
      },
      { timeout: 3_000 }
    )
    // The record has been read and the page has taken what it said.
    await flush()
    expect(screen.getByTestId('composer-send')).toBeDisabled()
    expect(screen.getByTestId('composer-reason')).toHaveTextContent(/no confirmed outcome yet/)
  })

  it('keeps holding an action the host records as accepted and not yet applied', async () => {
    // The answer carried only the action's identity, and the host has it as dispatching: a record
    // that is not final does not lift the hold on sending the text again.
    const recorded = { state: 'dispatching' as Receipt['state'] }
    const reads: string[] = []
    await sentOnce(UNCONFIRMED, recorded, reads)
    await waitFor(
      () => {
        expect(reads.length).toBeGreaterThan(0)
      },
      { timeout: 3_000 }
    )
    await flush()
    expect(screen.getByTestId('composer-send')).toBeDisabled()
    expect(screen.getByTestId('composer-reason')).toHaveTextContent(/no confirmed outcome yet/)
  })

  it('removes a prompt’s stored draft and its text when the host says it was applied after nobody knew', async () => {
    const recorded = { state: 'applied' as Receipt['state'] }
    const { device } = await sentOnce(UNCONFIRMED, recorded)
    await waitFor(
      () => {
        expect(device.all()).toEqual([])
      },
      { timeout: 3_000 }
    )
    expect(screen.getByTestId('composer-input')).toHaveValue('')
  })

  it('keeps holding an action with no confirmed outcome when the tab is closed and the session opened again', async () => {
    // The host's own record is unknown too, so nothing settles it.
    const recorded = { state: 'unknown' as Receipt['state'] }
    const device = new FakeDraftStore()
    const host = fakeHost({ drafts: device })
    render(
      <AppProvider
        port={answering(host.port, UNCONFIRMED, recorded)}
        initialPlace={{ view: 'session', sessionId: SESSION_MAIN, pane: 'semantic' }}
      >
        <App />
      </AppProvider>
    )
    const person = userEvent.setup()
    await person.type(await screen.findByTestId('composer-input'), 'run the migration')
    await waitFor(() => {
      expect(screen.getByTestId('composer-send')).toBeEnabled()
    })
    await person.click(screen.getByTestId('composer-send'))
    await waitFor(() => {
      expect(screen.getByTestId('composer-reason')).toHaveTextContent(/no confirmed outcome yet/)
    })

    // A second session's tab is open, so the first can be closed; closing it and coming back is a
    // new view of the session, and the hold stays.
    await person.click(screen.getByRole('button', { name: 'Sessions' }))
    await person.click(await screen.findByTestId('session-row-1'))
    await person.click(screen.getByRole('button', { name: 'Sessions' }))
    await person.click(await screen.findByTestId('session-row-2'))
    await person.click(await screen.findByRole('button', { name: 'Close the tab for session 01' }))
    await person.click(screen.getByRole('button', { name: 'Sessions' }))
    await person.click(await screen.findByTestId('session-row-1'))
    await waitFor(() => {
      expect(screen.getByTestId('composer-input')).toHaveValue('run the migration')
    })
    expect(screen.getByTestId('composer-send')).toBeDisabled()
    expect(screen.getByTestId('composer-reason')).toHaveTextContent(/no confirmed outcome yet/)
  })

  it('ends a prompt the host accepted, though the view that sent it was left before the answer', async () => {
    const device = new FakeDraftStore()
    const host = fakeHost({ drafts: device })
    let answer: (value: Settled<AgentMutationResult>) => void = () => undefined
    const late = new Promise<Settled<AgentMutationResult>>((resolve) => {
      answer = resolve
    })
    const recorded = { state: 'dispatching' as Receipt['state'] }
    render(
      <AppProvider
        port={{
          ...answering(host.port, WITH_THE_HOST, recorded),
          composerSubmit: () => late
        }}
        initialPlace={{ view: 'session', sessionId: SESSION_MAIN, pane: 'semantic' }}
      >
        <App />
      </AppProvider>
    )
    const person = userEvent.setup()
    await person.type(await screen.findByTestId('composer-input'), 'run the migration')
    await waitFor(() => {
      expect(screen.getByTestId('composer-send')).toBeEnabled()
    })
    await person.click(screen.getByTestId('composer-send'))
    // The Terminal pane takes the view away before the host answers.
    await person.click(screen.getByRole('tab', { name: 'Terminal' }))
    await waitFor(() => {
      expect(screen.queryByTestId('composer-input')).toBeNull()
    })
    await act(async () => {
      answer(WITH_THE_HOST)
      await Promise.resolve()
    })

    // The host applies it, and the person comes back: the record is read, and the prompt ends.
    recorded.state = 'applied'
    await person.click(screen.getByRole('tab', { name: 'Conversation' }))
    await waitFor(
      () => {
        expect(device.all()).toEqual([])
      },
      { timeout: 3_000 }
    )
    expect(await screen.findByTestId('composer-input')).toHaveValue('')
  })

  describe('whose tab is closed before the host answers', () => {
    /** The conversation, its prompt sent and its answer held, and the session's tab closed. */
    async function closedBeforeTheAnswer(recorded: Recorded) {
      const device = new FakeDraftStore()
      const host = fakeHost({ drafts: device })
      let answer: (value: Settled<AgentMutationResult>) => void = () => undefined
      const late = new Promise<Settled<AgentMutationResult>>((resolve) => {
        answer = resolve
      })
      render(
        <AppProvider
          port={{ ...answering(host.port, WITH_THE_HOST, recorded), composerSubmit: () => late }}
          initialPlace={{ view: 'session', sessionId: SESSION_MAIN, pane: 'semantic' }}
        >
          <App />
        </AppProvider>
      )
      const person = userEvent.setup()
      await person.type(await screen.findByTestId('composer-input'), 'run the migration')
      await waitFor(() => {
        expect(screen.getByTestId('composer-send')).toBeEnabled()
      })
      await person.click(screen.getByTestId('composer-send'))
      // A second session's tab is open, so the first can be closed while its prompt is on its way.
      await person.click(screen.getByRole('button', { name: 'Sessions' }))
      await person.click(await screen.findByTestId('session-row-1'))
      await person.click(screen.getByRole('button', { name: 'Sessions' }))
      await person.click(await screen.findByTestId('session-row-2'))
      await person.click(await screen.findByRole('button', { name: 'Close the tab for session 01' }))
      return {
        device,
        person,
        answer: async (value: Settled<AgentMutationResult>) => {
          await act(async () => {
            answer(value)
            await Promise.resolve()
          })
        },
        reopen: async () => {
          await person.click(screen.getByRole('button', { name: 'Sessions' }))
          await person.click(await screen.findByTestId('session-row-1'))
        }
      }
    }

    it('keeps holding an action the host then never confirmed', async () => {
      const closed = await closedBeforeTheAnswer({ state: 'unknown' })
      await closed.answer(UNCONFIRMED)
      await closed.reopen()

      await waitFor(() => {
        expect(screen.getByTestId('composer-input')).toHaveValue('run the migration')
      })
      expect(screen.getByTestId('composer-send')).toBeDisabled()
      expect(screen.getByTestId('composer-reason')).toHaveTextContent(/no confirmed outcome yet/)
    })

    it('ends a prompt the host accepted, and removes its stored draft, once the host applies it', async () => {
      const recorded = { state: 'dispatching' as Receipt['state'] }
      const closed = await closedBeforeTheAnswer(recorded)
      await closed.answer(WITH_THE_HOST)
      recorded.state = 'applied'
      await closed.reopen()

      await waitFor(
        () => {
          expect(closed.device.all()).toEqual([])
        },
        { timeout: 3_000 }
      )
      expect(await screen.findByTestId('composer-input')).toHaveValue('')
    })
  })

  it('does not take a record older than what it has, whatever an event left out', async () => {
    const device = new FakeDraftStore()
    const host = fakeHost({ drafts: device })
    const held: ((record: { receipt: Receipt; result: null }) => void)[] = []
    render(
      <AppProvider
        port={{
          ...answering(host.port, WITH_THE_HOST, { state: 'dispatching' }),
          actionRead: () =>
            new Promise((resolve) => {
              held.push(resolve)
            })
        }}
        initialPlace={{ view: 'session', sessionId: SESSION_MAIN, pane: 'semantic' }}
      >
        <App />
      </AppProvider>
    )
    const person = userEvent.setup()
    await person.type(await screen.findByTestId('composer-input'), 'run the migration')
    await waitFor(() => {
      expect(screen.getByTestId('composer-send')).toBeEnabled()
    })
    await person.click(screen.getByTestId('composer-send'))
    // The first read is on its way, asked when the action was at its first revision.
    await waitFor(() => {
      expect(held).toHaveLength(1)
    })
    const states = () =>
      [...screen.getByTestId('pending-actions').querySelectorAll('li')].map((each) => each.dataset.state)
    const emit = (sequence: string, receipt: unknown) => {
      act(() => {
        host.controls.emit({
          stream_id: `receipts:${SESSION_MAIN}`,
          sequence,
          body: { kind: 'receipt', receipt }
        })
      })
    }

    // The host moves the action on, and then an event says where it is and carries no revision.
    emit('1', { ...receiptAt('dispatching'), revision: '3' })
    emit('2', { ...receiptAt('dispatching'), revision: undefined })
    // The read that was on its way answers last, with a record that is newer than the one it was
    // asked at and older than the event.
    await act(async () => {
      held[0]?.({ receipt: { ...receiptAt('unknown'), revision: '2' }, result: null })
      await Promise.resolve()
    })
    await flush()
    expect(states()).toEqual(['sent'])
    expect(screen.getByTestId('composer-reason')).not.toHaveTextContent(/no confirmed outcome/)

    // What the host says next is taken.
    emit('3', { ...receiptAt('applied'), revision: '4' })
    await waitFor(() => {
      expect(states()).toEqual(['applied'])
    })
  })

  it('does not call a prompt taken while the host has only accepted it', async () => {
    const recorded = { state: 'dispatching' as Receipt['state'] }
    const { device, controls } = await sentOnce(WITH_THE_HOST, recorded)
    await waitFor(() => {
      expect(screen.getByTestId('composer-input')).toHaveValue('')
    })
    await screen.findByTestId('pending-actions')
    // The stored draft is exactly what was sent, and stays until the host has applied it.
    expect(device.all().map((draft) => draft.text)).toEqual(['run the migration'])

    act(() => {
      controls.emit({
        stream_id: `receipts:${SESSION_MAIN}`,
        sequence: '1',
        body: { kind: 'receipt', receipt: receiptAt('applied') }
      })
    })
    await waitFor(() => {
      expect(device.all()).toEqual([])
    })
  })
})

describe('on the phone', () => {
  /** The phone's session screen, with the person's text sent once. */
  async function sentOnce(
    answer: Settled<AgentMutationResult> | ((attempt: number) => Settled<AgentMutationResult>),
    recorded: Recorded,
    reads: string[] = [],
    sent: unknown[] = []
  ) {
    const device = new FakeDraftStore()
    const host = fakeHost({ drafts: device })
    render(
      <AppProvider port={answering(host.port, answer, recorded, reads, sent)}>
        <MobileApp surface="ios" storage={null} />
      </AppProvider>
    )
    const person = userEvent.setup()
    await person.click(await screen.findByRole('button', { name: /^Sessions/ }))
    await person.click(await screen.findByRole('button', { name: /Session 1/ }))
    await person.type(await screen.findByLabelText('Message this session'), 'run the migration')
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Send' })).toBeEnabled()
    })
    await person.click(screen.getByRole('button', { name: 'Send' }))
    return { ...host, device, person }
  }

  it('settles an action whose outcome was never confirmed by asking the host, and then sends again', async () => {
    const recorded = { state: 'applied' as Receipt['state'] }
    const reads: string[] = []
    const { person } = await sentOnce(UNCONFIRMED, recorded, reads)

    await waitFor(
      () => {
        expect(reads).toContain(ACTION)
        expect(screen.queryByText(/no confirmed outcome yet/)).toBeNull()
      },
      { timeout: 3_000 }
    )
    const field = screen.getByLabelText('Message this session')
    await person.clear(field)
    await person.type(field, 'the next thing')
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Send' })).toBeEnabled()
    })
  })

  it('keeps holding an action the host itself still records as unknown', async () => {
    const recorded = { state: 'unknown' as Receipt['state'] }
    const reads: string[] = []
    await sentOnce(UNCONFIRMED, recorded, reads)
    await waitFor(
      () => {
        expect(reads).toContain(ACTION)
      },
      { timeout: 3_000 }
    )
    expect(screen.getByText(/no confirmed outcome yet/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Send' })).toBeDisabled()
  })

  it('does not call a prompt taken while the host has only accepted it', async () => {
    const recorded = { state: 'dispatching' as Receipt['state'] }
    const reads: string[] = []
    const { device } = await sentOnce(WITH_THE_HOST, recorded, reads)
    await waitFor(() => {
      expect(screen.getByLabelText('Message this session')).toHaveValue('')
    })
    await waitFor(
      () => {
        expect(reads).toContain(ACTION)
      },
      { timeout: 3_000 }
    )
    // The host's record still says dispatching: the stored draft is exactly what was sent.
    expect(device.all().map((draft) => draft.text)).toEqual(['run the migration'])
  })

  it('removes the text of a prompt that nobody knew the end of when the application had started again, once the host says it was applied', async () => {
    const storage = fakeStorage()
    const device = new FakeDraftStore()
    const person = userEvent.setup()
    const run = (recorded: Recorded) => {
      const host = fakeHost({ drafts: device })
      return render(
        <AppProvider port={answering(host.port, UNCONFIRMED, recorded)}>
          <MobileApp surface="ios" storage={storage} />
        </AppProvider>
      )
    }
    // The first run sends a prompt and is never told what became of it, and then ends.
    const first = run({ state: 'unknown' })
    await person.click(await screen.findByRole('button', { name: /^Sessions/ }))
    await person.click(await screen.findByRole('button', { name: /Session 1/ }))
    await person.type(await screen.findByLabelText('Message this session'), 'run the migration')
    await person.click(screen.getByRole('button', { name: 'Send' }))
    await screen.findByText(/no confirmed outcome yet/)
    first.unmount()

    // The next run finds the text under its stored draft, held: nobody knows yet what became of it.
    run({ state: 'applied' })
    await person.click(await screen.findByRole('button', { name: /^Sessions/ }))
    await person.click(await screen.findByRole('button', { name: /Session 1/ }))
    expect(await screen.findByLabelText('Message this session')).toBeInTheDocument()

    // The host's record says it was applied: the text goes, and the store keeps nothing of it.
    await waitFor(
      () => {
        expect(screen.getByLabelText('Message this session')).toHaveValue('')
      },
      { timeout: 3_000 }
    )
    await waitFor(() => {
      expect(device.all()).toEqual([])
    })
  })

  it('removes the stored draft once the host has applied the prompt', async () => {
    const recorded = { state: 'applied' as Receipt['state'] }
    const { device } = await sentOnce(WITH_THE_HOST, recorded)
    await waitFor(
      () => {
        expect(device.all()).toEqual([])
      },
      { timeout: 3_000 }
    )
  })
})

describe('two windows of the desktop application that hold one draft', () => {
  /** One window of the application over the device's drafts, with the sends its host received. */
  function open(device: FakeDraftStore) {
    const host = fakeHost({ drafts: device })
    const view = render(
      <AppProvider
        port={host.port}
        initialPlace={{ view: 'session', sessionId: SESSION_MAIN, pane: 'semantic' }}
      >
        <App />
      </AppProvider>
    )
    return { ...host, within: within(view.container) }
  }

  it('send it once: the second window is refused and keeps what it held', async () => {
    const device = new FakeDraftStore()
    const person = userEvent.setup()
    const first = open(device)
    await person.type(await first.within.findByTestId('composer-input'), 'run the migration')
    await waitFor(() => {
      expect(device.all().map((draft) => draft.text)).toEqual(['run the migration'])
    })
    const second = open(device)
    await waitFor(() => {
      expect(second.within.getByTestId('composer-input')).toHaveValue('run the migration')
    })
    await waitFor(() => {
      expect(second.within.getByTestId('composer-send')).toBeEnabled()
    })

    await person.click(first.within.getByTestId('composer-send'))
    await waitFor(() => {
      expect(first.controls.submissions).toBe(1)
    })
    await waitFor(() => {
      expect(device.all()).toEqual([])
    })

    // The second window still shows the draft, and its Send is refused: nothing reaches its host,
    // no entry says the host refused anything, and the text stays.
    await person.click(second.within.getByTestId('composer-send'))
    await waitFor(() => {
      expect(second.within.getByTestId('composer-input')).toHaveValue('run the migration')
    })
    await waitFor(() => {
      expect(second.within.queryByTestId('pending-actions')).toBeNull()
    })
    expect(second.controls.submissions).toBe(0)
    expect(first.controls.submissions).toBe(1)
  })
})
