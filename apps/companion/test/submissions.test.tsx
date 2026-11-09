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
import { afterEach, describe, expect, it, vi } from 'vitest'

import type { AgentMutationResult, Receipt } from '@kalareach/protocol'

import { App } from '../src/App'
import { AppProvider } from '../src/app/state'
import { fakeHost } from '../src/host/fake'
import { FakeDraftStore } from '../src/host/fake-drafts'
import type { HostPort, Settled } from '../src/host/port'
import type { Supersession } from '../src/model/receipt-reads'
import { MobileApp } from '../src/mobile/MobileApp'

const SESSION_MAIN = '8a7b6c50-22bb-4c3d-8e4f-000000000101'
const ACTION = '00000000-0000-4000-8000-00000000abcd'
/** The action of a prompt sent a second time, a new action of its own. */
const ANOTHER_ACTION = '00000000-0000-4000-8000-00000000abce'
/** The action of a prompt sent after the host refused a quote, a third of its own. */
const THIRD_ACTION = '00000000-0000-4000-8000-00000000abcf'
/** An hour, which the window's clock steps back by in the cases that step it. */
const STEP_BACK_MS = 3_600_000

afterEach(cleanup)

/** A receipt of a prompt's action, at the state and revision the host last recorded. */
function receiptAt(state: Receipt['state'], action = ACTION, revision = '1'): Receipt {
  return {
    action_id: action,
    actor_id: 'owner:local',
    error: null,
    method: 'agent.prompt.submit',
    method_version: 1,
    payload_digest: '0'.repeat(64),
    reason: null,
    revision,
    state,
    updated_at_ms: '0',
    accepted_deadline_ms: null
  }
}

/** The answer of a host that never confirmed what became of the request: only its identity. */
const UNCONFIRMED: Settled<AgentMutationResult> = { receipt: null, value: null, action_id: ACTION }

/** The answer of a host that has the request and is not done with it. */
const WITH_THE_HOST: Settled<AgentMutationResult> = { receipt: receiptAt('dispatching'), value: null, action_id: ACTION }

/** What a send comes to: the host's answer, or a refusal. */
type Given = Settled<AgentMutationResult> | Error

/** What the host recorded of the actions: one state for all, or a state for each action named. */
interface Recorded {
  state: Receipt['state']
  byAction?: Record<string, Receipt['state']>
  /** The revision the host's record stands at; the first by default. */
  revision?: string
  /** True when the host cannot be asked what it recorded. */
  unreadable?: boolean
  /**
   * Makes the host hold a quote to the worker's rule: it is admitted only at the revision the
   * record stands at now, and only when this device was shown that revision by a read. Deleting
   * from `shown` is the worker having forgotten what it showed, as a restart does.
   */
  worker?: { readonly shown: Map<string, string> }
}

/** The refusal a worker makes of a quote it will not take. */
const QUOTE_REFUSED = Object.assign(new Error('the earlier result has not been shown'), {
  code: 'DRAFT_CONFLICT',
  message: 'the earlier result has not been shown',
  user_action: 'retry'
})

/**
 * A port whose prompts are answered with `answer` (or, for the one asked for the nth time, with
 * what a function of n says), and whose record of an action is `recorded`.
 */
function answering(
  port: HostPort,
  answer: Given | ((attempt: number) => Given),
  recorded: Recorded,
  reads: string[] = [],
  sent: unknown[] = [],
  quotes: (Supersession | undefined)[] = []
): HostPort {
  return {
    ...port,
    composerSubmit: (params, _opening, supersedes) => {
      sent.push(params)
      quotes.push(supersedes)
      if (supersedes !== undefined && recorded.worker !== undefined) {
        const current = recorded.revision ?? '1'
        if (supersedes.revision !== current || recorded.worker.shown.get(supersedes.action_id) !== current) {
          return Promise.reject(QUOTE_REFUSED)
        }
      }
      const given = typeof answer === 'function' ? answer(sent.length) : answer
      return given instanceof Error ? Promise.reject(given) : Promise.resolve(given)
    },
    actionRead: (params) => {
      reads.push(params.action_id)
      if (recorded.unreadable === true) return Promise.reject(new Error('the host did not answer'))
      recorded.worker?.shown.set(params.action_id, recorded.revision ?? '1')
      const state = recorded.byAction?.[params.action_id] ?? recorded.state
      return Promise.resolve({
        receipt: receiptAt(state, params.action_id, recorded.revision),
        result: null
      })
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
    answer: Given | ((attempt: number) => Given),
    recorded: Recorded,
    reads: string[] = [],
    sent: unknown[] = [],
    quotes: (Supersession | undefined)[] = []
  ) {
    const device = new FakeDraftStore()
    const host = fakeHost({ drafts: device })
    render(
      <AppProvider
        port={answering(host.port, answer, recorded, reads, sent, quotes)}
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
    expect(screen.getByTestId('composer-reason')).toHaveTextContent(/may still run/)
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

  describe('whose outcome nobody knows', () => {
    /** The first prompt has no confirmed outcome; the one sent after it is accepted. */
    const SECOND: Settled<AgentMutationResult> = {
      receipt: receiptAt('dispatching', ANOTHER_ACTION),
      value: null,
      action_id: ANOTHER_ACTION
    }
    const answers = (attempt: number) => (attempt === 1 ? UNCONFIRMED : SECOND)

    it('can be sent again by a person who checked, as a new action, and stays listed as unknown', async () => {
      const recorded: Recorded = { state: 'unknown', byAction: { [ANOTHER_ACTION]: 'dispatching' } }
      const sent: unknown[] = []
      const { person } = await sentOnce(answers, recorded, [], sent)

      // The risk is named beside the way past it, and the plain Send stays off.
      const release = await screen.findByTestId('composer-send-anyway')
      expect(release).toBeEnabled()
      expect(release).toHaveTextContent(/I checked; send anyway/)
      expect(screen.getByTestId('composer-reason')).toHaveTextContent(/may still run/)
      expect(screen.getByTestId('composer-reason')).toHaveTextContent(/twice/)
      expect(screen.getByTestId('composer-send')).toBeDisabled()
      expect(sent).toHaveLength(1)

      await person.click(release)
      await waitFor(() => {
        expect(sent).toHaveLength(2)
      })
      expect(sent[1]).toMatchObject({ text: 'run the migration' })
      const states = () =>
        [...screen.getByTestId('pending-actions').querySelectorAll('li')].map((each) => each.dataset.state)
      await waitFor(() => {
        expect(states()).toEqual(['unknown', 'sent'])
      })

      // The earlier action still has no confirmed outcome, so the plain Send is still off.
      await waitFor(() => {
        expect(screen.getByTestId('composer-input')).toHaveValue('')
      })
      await person.type(screen.getByTestId('composer-input'), 'and then the next')
      expect(screen.getByTestId('composer-send')).toBeDisabled()
      expect(screen.getByTestId('composer-send-anyway')).toBeEnabled()
    })

    it('names the earlier action and the revision it read when the person sends anyway', async () => {
      const recorded: Recorded = {
        state: 'unknown',
        revision: '3',
        byAction: { [ANOTHER_ACTION]: 'dispatching' }
      }
      const reads: string[] = []
      const quotes: (Supersession | undefined)[] = []
      const { person } = await sentOnce(answers, recorded, reads, [], quotes)

      // The record is read, and the person is shown it as unknown: that is what they checked.
      await waitFor(
        () => {
          expect(reads).toContain(ACTION)
        },
        { timeout: 3_000 }
      )
      await flush()
      await person.click(await screen.findByTestId('composer-send-anyway'))
      await waitFor(() => {
        expect(quotes).toHaveLength(2)
      })
      expect(quotes[0]).toBeUndefined()
      expect(quotes[1]).toEqual({ action_id: ACTION, revision: '3' })
    })

    it('names nothing when the earlier record could not be read, and leaves the refusal to the host', async () => {
      const recorded: Recorded = { state: 'unknown', unreadable: true }
      const quotes: (Supersession | undefined)[] = []
      const { person } = await sentOnce(answers, recorded, [], [], quotes)
      await person.click(await screen.findByTestId('composer-send-anyway'))
      await waitFor(() => {
        expect(quotes).toHaveLength(2)
      })
      expect(quotes[1]).toBeUndefined()
    })

    it('names nothing when the host holds the earlier action as only dispatching', async () => {
      // The page keeps an outcome it was told nobody knows as unknown until the host says it is
      // final; the host's own record says it still has the action, which stands in no prompt's way.
      const recorded: Recorded = { state: 'dispatching', revision: '2' }
      const reads: string[] = []
      const quotes: (Supersession | undefined)[] = []
      const { person } = await sentOnce(answers, recorded, reads, [], quotes)
      await waitFor(
        () => {
          expect(reads).toContain(ACTION)
        },
        { timeout: 3_000 }
      )
      await flush()
      await person.click(await screen.findByTestId('composer-send-anyway'))
      await waitFor(() => {
        expect(quotes).toHaveLength(2)
      })
      expect(quotes[1]).toBeUndefined()
    })

    it('reads the earlier record again at once when the host refuses the quote, so the next press quotes what it says now', async () => {
      const refused = Object.assign(new Error('the earlier result has not been shown'), {
        code: 'DRAFT_CONFLICT',
        message: 'the earlier result has not been shown',
        user_action: 'retry'
      })
      const recorded: Recorded = { state: 'unknown', revision: '3' }
      const reads: string[] = []
      const quotes: (Supersession | undefined)[] = []
      const { person } = await sentOnce(
        (attempt) => {
          // The host's record moves on while the prompt is on its way, after the page read it.
          if (attempt === 2) recorded.revision = '4'
          return attempt === 1 ? UNCONFIRMED : attempt === 2 ? refused : UNCONFIRMED
        },
        recorded,
        reads,
        [],
        quotes
      )
      await waitFor(
        () => {
          expect(reads).toContain(ACTION)
        },
        { timeout: 3_000 }
      )
      await flush()
      await person.click(await screen.findByTestId('composer-send-anyway'))
      await waitFor(() => {
        expect(screen.getByTestId('composer-input')).toHaveValue('run the migration')
      })
      expect(quotes[1]).toEqual({ action_id: ACTION, revision: '3' })
      // The refusal is the host's word that the record is not what was shown, and the page reads it
      // again at once: the next press quotes the revision that is there now.
      await person.click(await screen.findByTestId('composer-send-anyway'))
      await waitFor(() => {
        expect(quotes).toHaveLength(3)
      })
      expect(quotes[2]).toEqual({ action_id: ACTION, revision: '4' })
    })

    // KR-REQ-23.24: the later request the person makes names the record the host holds when they
    // press, and nothing is sent past a result that was settled since they looked.
    describe('read again by the person who sends anyway', () => {
      const states = () =>
        [...screen.getByTestId('pending-actions').querySelectorAll('li')].map((each) => each.dataset.state)
      const answers = (attempt: number) =>
        attempt === 1
          ? UNCONFIRMED
          : { receipt: receiptAt('dispatching', ANOTHER_ACTION), value: null, action_id: ANOTHER_ACTION }

      it('names the revision the host holds at the press when the worker no longer remembers showing it', async () => {
        // A worker that restarted forgot what it showed this device, and refuses a quote of a record
        // the device was not shown by a read it still holds.
        const recorded: Recorded = {
          state: 'unknown',
          revision: '3',
          byAction: { [ANOTHER_ACTION]: 'dispatching' },
          worker: { shown: new Map() }
        }
        const reads: string[] = []
        const quotes: (Supersession | undefined)[] = []
        const { person } = await sentOnce(answers, recorded, reads, [], quotes)
        await waitFor(
          () => {
            expect(reads).toContain(ACTION)
          },
          { timeout: 3_000 }
        )
        await flush()
        recorded.worker?.shown.clear()
        const before = reads.length
        await person.click(await screen.findByTestId('composer-send-anyway'))
        await waitFor(() => {
          expect(states()).toEqual(['unknown', 'sent'])
        })
        expect(reads.length).toBeGreaterThan(before)
        expect(quotes[1]).toEqual({ action_id: ACTION, revision: '3' })
      })

      it('names the revision it reads at the press, not the one it read before', async () => {
        // A state only a scripted host reaches: a real record that is unknown moves only to applied
        // or refused. It tells the revision read at the press from the revision read before it.
        const recorded: Recorded = {
          state: 'unknown',
          revision: '3',
          byAction: { [ANOTHER_ACTION]: 'dispatching' },
          worker: { shown: new Map() }
        }
        const reads: string[] = []
        const quotes: (Supersession | undefined)[] = []
        const { person } = await sentOnce(answers, recorded, reads, [], quotes)
        await waitFor(
          () => {
            expect(reads).toContain(ACTION)
          },
          { timeout: 3_000 }
        )
        await flush()
        recorded.revision = '4'
        await person.click(await screen.findByTestId('composer-send-anyway'))
        await waitFor(() => {
          expect(states()).toEqual(['unknown', 'sent'])
        })
        expect(quotes[1]).toEqual({ action_id: ACTION, revision: '4' })
      })

      it('sends nothing and shows the result when the record has become applied', async () => {
        const recorded: Recorded = { state: 'unknown', revision: '3' }
        const reads: string[] = []
        const sent: unknown[] = []
        const { person } = await sentOnce(answers, recorded, reads, sent)
        await waitFor(
          () => {
            expect(reads).toContain(ACTION)
          },
          { timeout: 3_000 }
        )
        await flush()
        recorded.state = 'applied'
        recorded.revision = '5'
        await person.click(await screen.findByTestId('composer-send-anyway'))
        await waitFor(() => {
          expect(states()).toEqual(['applied'])
        })
        await flush()
        expect(sent).toHaveLength(1)
        // The words were done once: nothing keeps them in the composer for a second send.
        expect(screen.getByTestId('composer-input')).toHaveValue('')
      })

      it('sends nothing, and gives the text back, when the record has become refused', async () => {
        const recorded: Recorded = { state: 'unknown', revision: '3' }
        const reads: string[] = []
        const sent: unknown[] = []
        const { person } = await sentOnce(answers, recorded, reads, sent)
        await waitFor(
          () => {
            expect(reads).toContain(ACTION)
          },
          { timeout: 3_000 }
        )
        await flush()
        recorded.state = 'refused'
        recorded.revision = '5'
        await person.click(await screen.findByTestId('composer-send-anyway'))
        await waitFor(() => {
          expect(states()).toEqual(['refused'])
        })
        await flush()
        expect(sent).toHaveLength(1)
        expect(screen.getByTestId('composer-input')).toHaveValue('run the migration')
      })

      it('names what it read last when the host cannot be asked at the press', async () => {
        const recorded: Recorded = { state: 'unknown', revision: '3' }
        const reads: string[] = []
        const quotes: (Supersession | undefined)[] = []
        const { person } = await sentOnce(answers, recorded, reads, [], quotes)
        await waitFor(
          () => {
            expect(reads).toContain(ACTION)
          },
          { timeout: 3_000 }
        )
        await flush()
        recorded.unreadable = true
        await person.click(await screen.findByTestId('composer-send-anyway'))
        await waitFor(() => {
          expect(quotes).toHaveLength(2)
        })
        expect(quotes[1]).toEqual({ action_id: ACTION, revision: '3' })
      })
    })

    it('names the action the host named when it refused the quote of another that the page picked', async () => {
      // Two earlier prompts have no confirmed outcome, and both records read alike, so the page
      // picks the later identifier. The host's newest is the other, and its refusal says so.
      const unconfirmed = (action: string): Settled<AgentMutationResult> => ({
        receipt: null,
        value: null,
        action_id: action
      })
      const refused = Object.assign(new Error('the quote was not the newest'), {
        code: 'DRAFT_CONFLICT',
        message: `DRAFT_CONFLICT: the uncertain outcome of this subject is action ${ACTION}, not ${ANOTHER_ACTION}`,
        user_action: 'retry'
      })
      const recorded: Recorded = { state: 'unknown', revision: '3' }
      const reads: string[] = []
      const quotes: (Supersession | undefined)[] = []
      const { person } = await sentOnce(
        (attempt) =>
          attempt === 1
            ? unconfirmed(ACTION)
            : attempt === 2
              ? unconfirmed(ANOTHER_ACTION)
              : attempt === 3
                ? refused
                : unconfirmed(ACTION),
        recorded,
        reads,
        [],
        quotes
      )
      await waitFor(
        () => {
          expect(reads).toContain(ACTION)
        },
        { timeout: 3_000 }
      )
      await flush()
      await person.click(await screen.findByTestId('composer-send-anyway'))
      await waitFor(() => {
        expect(quotes).toHaveLength(2)
      })
      await waitFor(
        () => {
          expect(reads).toContain(ANOTHER_ACTION)
        },
        { timeout: 3_000 }
      )
      await flush()

      // The page quotes the later identifier, and the host refuses it, naming the other. An
      // outcome nobody knows leaves the words in the composer, and a refusal leaves them there too.
      await waitFor(() => {
        expect(screen.getByTestId('composer-send-anyway')).toBeEnabled()
      })
      await person.click(screen.getByTestId('composer-send-anyway'))
      await waitFor(() => {
        expect(quotes).toHaveLength(3)
      })
      expect(quotes[2]).toEqual({ action_id: ANOTHER_ACTION, revision: '3' })
      await screen.findAllByText(/the uncertain outcome of this subject is action/)

      // The next press quotes the action the refusal named.
      await waitFor(() => {
        expect(screen.getByTestId('composer-send-anyway')).toBeEnabled()
      })
      await person.click(screen.getByTestId('composer-send-anyway'))
      await waitFor(() => {
        expect(quotes).toHaveLength(4)
      })
      expect(quotes[3]).toEqual({ action_id: ACTION, revision: '3' })
    })

    it('quotes a prompt made after the refusal when the window\'s clock has stepped back since', async () => {
      const unconfirmed = (action: string): Settled<AgentMutationResult> => ({
        receipt: null,
        value: null,
        action_id: action
      })
      const refused = Object.assign(new Error('the quote was not the newest'), {
        code: 'DRAFT_CONFLICT',
        message: `DRAFT_CONFLICT: the uncertain outcome of this subject is action ${ACTION}, not ${ANOTHER_ACTION}`,
        user_action: 'retry'
      })
      const recorded: Recorded = { state: 'unknown', revision: '3' }
      const reads: string[] = []
      const quotes: (Supersession | undefined)[] = []
      const real = Date.now.bind(Date)
      let stepped = 0
      const clock = vi.spyOn(Date, 'now').mockImplementation(() => real() - stepped)
      try {
        const { person } = await sentOnce(
          (attempt) =>
            attempt === 1
              ? unconfirmed(ACTION)
              : attempt === 2
                ? unconfirmed(ANOTHER_ACTION)
                : attempt === 3
                  ? refused
                  : unconfirmed(THIRD_ACTION),
          recorded,
          reads,
          [],
          quotes
        )
        await waitFor(
          () => {
            expect(reads).toContain(ACTION)
          },
          { timeout: 3_000 }
        )
        await flush()
        await person.click(await screen.findByTestId('composer-send-anyway'))
        await waitFor(() => {
          expect(quotes).toHaveLength(2)
        })
        await waitFor(
          () => {
            expect(reads).toContain(ANOTHER_ACTION)
          },
          { timeout: 3_000 }
        )
        await flush()
        await waitFor(() => {
          expect(screen.getByTestId('composer-send-anyway')).toBeEnabled()
        })
        // The host refuses the quote of the later identifier, naming the other.
        await person.click(screen.getByTestId('composer-send-anyway'))
        await waitFor(() => {
          expect(quotes).toHaveLength(3)
        })
        await screen.findAllByText(/the uncertain outcome of this subject is action/)

        // The window's clock steps back. The next press quotes the action the refusal named, and
        // its prompt is made after that refusal whatever the clock says.
        stepped = STEP_BACK_MS
        await waitFor(() => {
          expect(screen.getByTestId('composer-send-anyway')).toBeEnabled()
        })
        await person.click(screen.getByTestId('composer-send-anyway'))
        await waitFor(() => {
          expect(quotes).toHaveLength(4)
        })
        expect(quotes[3]?.action_id).toBe(ACTION)
        await waitFor(
          () => {
            expect(reads).toContain(THIRD_ACTION)
          },
          { timeout: 3_000 }
        )
        await flush()
        await waitFor(() => {
          expect(screen.getByTestId('composer-send-anyway')).toBeEnabled()
        })
        await person.click(screen.getByTestId('composer-send-anyway'))
        await waitFor(() => {
          expect(quotes).toHaveLength(5)
        })
        expect(quotes[4]).toEqual({ action_id: THIRD_ACTION, revision: '3' })
      } finally {
        clock.mockRestore()
      }
    })

    it('is not offered a way past while the host merely has the action', async () => {
      const recorded = { state: 'dispatching' as Receipt['state'] }
      await sentOnce(WITH_THE_HOST, recorded)
      await waitFor(() => {
        expect(screen.getByTestId('pending-actions')).toBeInTheDocument()
      })
      expect(screen.queryByTestId('composer-send-anyway')).toBeNull()
    })

    it('does not put the text back when the second send is refused after the first was applied', async () => {
      // Both sends of the same words end with nobody knowing; then the host says the first was
      // applied, and later that the second was refused.
      const SECOND_UNKNOWN: Settled<AgentMutationResult> = { receipt: null, value: null, action_id: ANOTHER_ACTION }
      const recorded: Recorded = { state: 'unknown' }
      const sent: unknown[] = []
      const { controls, person } = await sentOnce(
        (attempt) => (attempt === 1 ? UNCONFIRMED : SECOND_UNKNOWN),
        recorded,
        [],
        sent
      )
      await person.click(await screen.findByTestId('composer-send-anyway'))
      await waitFor(() => {
        expect(sent).toHaveLength(2)
      })
      const states = () =>
        [...screen.getByTestId('pending-actions').querySelectorAll('li')].map((each) => each.dataset.state)
      await waitFor(() => {
        expect(states()).toEqual(['unknown', 'unknown'])
      })
      const emit = (sequence: string, receipt: Receipt) => {
        act(() => {
          controls.emit({
            stream_id: `receipts:${SESSION_MAIN}`,
            sequence,
            body: { kind: 'receipt', receipt }
          })
        })
      }

      emit('1', receiptAt('applied', ACTION))
      await waitFor(() => {
        expect(screen.getByTestId('composer-input')).toHaveValue('')
      })
      emit('2', receiptAt('refused', ANOTHER_ACTION))
      await waitFor(() => {
        expect(states()).toEqual(['applied', 'refused'])
      })
      await flush()

      // The words were done once: nothing puts them back for a third send.
      expect(screen.getByTestId('composer-input')).toHaveValue('')
    })
  })

  it('does not put the text back when the second send answers as unknown after the first was applied, and is then refused', async () => {
    const device = new FakeDraftStore()
    const host = fakeHost({ drafts: device })
    const recorded: Recorded = { state: 'unknown' }
    let answer: (value: Settled<AgentMutationResult>) => void = () => undefined
    const second = new Promise<Settled<AgentMutationResult>>((resolve) => {
      answer = resolve
    })
    let attempts = 0
    const port: HostPort = {
      ...answering(host.port, UNCONFIRMED, recorded),
      composerSubmit: () => {
        attempts += 1
        return attempts === 1 ? Promise.resolve(UNCONFIRMED) : second
      }
    }
    render(
      <AppProvider
        port={port}
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
    await person.click(await screen.findByTestId('composer-send-anyway'))
    await waitFor(() => {
      expect(attempts).toBe(2)
    })
    const states = () =>
      [...screen.getByTestId('pending-actions').querySelectorAll('li')].map((each) => each.dataset.state)
    const emit = (sequence: string, receipt: Receipt) => {
      act(() => {
        host.controls.emit({
          stream_id: `receipts:${SESSION_MAIN}`,
          sequence,
          body: { kind: 'receipt', receipt }
        })
      })
    }

    // The first is applied while the second is on its way, and the second then says nobody knows.
    emit('1', receiptAt('applied', ACTION))
    await waitFor(() => {
      expect(states()).toEqual(['applied', 'queued'])
    })
    await act(async () => {
      answer({ receipt: null, value: null, action_id: ANOTHER_ACTION })
      await Promise.resolve()
    })
    await waitFor(() => {
      expect(states()).toEqual(['applied', 'unknown'])
    })
    emit('2', receiptAt('refused', ANOTHER_ACTION))
    await waitFor(() => {
      expect(states()).toEqual(['applied', 'refused'])
    })
    await flush()

    // The words were done once: nothing puts them back for a third send.
    expect(screen.getByTestId('composer-input')).toHaveValue('')
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
    answer: Given | ((attempt: number) => Given),
    recorded: Recorded,
    reads: string[] = [],
    sent: unknown[] = [],
    quotes: (Supersession | undefined)[] = []
  ) {
    const device = new FakeDraftStore()
    const host = fakeHost({ drafts: device })
    render(
      <AppProvider port={answering(host.port, answer, recorded, reads, sent, quotes)}>
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

  it('can be sent again by a person who checked an outcome nobody knows, as a new action', async () => {
    const recorded: Recorded = { state: 'unknown', byAction: { [ANOTHER_ACTION]: 'applied' } }
    const sent: unknown[] = []
    const second: Settled<AgentMutationResult> = {
      receipt: receiptAt('dispatching', ANOTHER_ACTION),
      value: null,
      action_id: ANOTHER_ACTION
    }
    const { person } = await sentOnce((attempt) => (attempt === 1 ? UNCONFIRMED : second), recorded, [], sent)

    const release = await screen.findByRole('button', { name: 'I checked; send anyway' })
    expect(release).toBeEnabled()
    expect(screen.getByText(/may still run/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Send' })).toBeDisabled()

    await person.click(release)
    await waitFor(() => {
      expect(sent).toHaveLength(2)
    })
    expect(sent[1]).toMatchObject({ text: 'run the migration' })
    // The second action is applied, and the first, which nobody knows, is listed with its own
    // status and still holds the session.
    expect(await screen.findByText('Applied', {}, { timeout: 3_000 })).toBeInTheDocument()
    const earlier = screen.getByTestId('earlier-actions')
    expect(within(earlier).getByText('Outcome unknown')).toBeInTheDocument()
    expect(within(earlier).getByText('run the migration')).toBeInTheDocument()
    expect(screen.getByText(/One action has no confirmed outcome yet/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Send' })).toBeDisabled()
  })

  it('names the earlier action and the revision it read when the person sends anyway', async () => {
    const recorded: Recorded = {
      state: 'unknown',
      revision: '3',
      byAction: { [ANOTHER_ACTION]: 'applied' }
    }
    const reads: string[] = []
    const quotes: (Supersession | undefined)[] = []
    const second: Settled<AgentMutationResult> = {
      receipt: receiptAt('dispatching', ANOTHER_ACTION),
      value: null,
      action_id: ANOTHER_ACTION
    }
    const { person } = await sentOnce(
      (attempt) => (attempt === 1 ? UNCONFIRMED : second),
      recorded,
      reads,
      [],
      quotes
    )
    await waitFor(
      () => {
        expect(reads).toContain(ACTION)
      },
      { timeout: 3_000 }
    )
    await flush()
    await person.click(await screen.findByRole('button', { name: 'I checked; send anyway' }))
    await waitFor(() => {
      expect(quotes).toHaveLength(2)
    })
    expect(quotes[0]).toBeUndefined()
    expect(quotes[1]).toEqual({ action_id: ACTION, revision: '3' })
  })

  // KR-REQ-23.24: the later request the person makes names the record the host holds when they
  // press, and nothing is sent past a result that was settled since they looked.
  describe('read again by the person who sends anyway', () => {
    const second: Settled<AgentMutationResult> = {
      receipt: receiptAt('dispatching', ANOTHER_ACTION),
      value: null,
      action_id: ANOTHER_ACTION
    }
    const answers = (attempt: number) => (attempt === 1 ? UNCONFIRMED : second)
    const release = () => screen.findByRole('button', { name: 'I checked; send anyway' })
    /** Waits until the page has read the earlier record and the screen has settled. */
    async function readOnce(reads: string[]): Promise<void> {
      await waitFor(
        () => {
          expect(reads).toContain(ACTION)
        },
        { timeout: 3_000 }
      )
      await flush()
    }

    it('names the revision the host holds at the press when the worker no longer remembers showing it', async () => {
      const recorded: Recorded = {
        state: 'unknown',
        revision: '3',
        byAction: { [ANOTHER_ACTION]: 'applied' },
        worker: { shown: new Map() }
      }
      const reads: string[] = []
      const quotes: (Supersession | undefined)[] = []
      const { person } = await sentOnce(answers, recorded, reads, [], quotes)
      await readOnce(reads)
      recorded.worker?.shown.clear()
      const before = reads.length
      await person.click(await release())
      await waitFor(() => {
        expect(quotes).toHaveLength(2)
      })
      expect(reads.length).toBeGreaterThan(before)
      expect(quotes[1]).toEqual({ action_id: ACTION, revision: '3' })
      expect(await screen.findByText('Applied', {}, { timeout: 3_000 })).toBeInTheDocument()
    })

    it('names the revision it reads at the press, not the one it read before', async () => {
      // A state only a scripted host reaches: a real record that is unknown moves only to applied
      // or refused. It tells the revision read at the press from the revision read before it.
      const recorded: Recorded = {
        state: 'unknown',
        revision: '3',
        byAction: { [ANOTHER_ACTION]: 'applied' },
        worker: { shown: new Map() }
      }
      const reads: string[] = []
      const quotes: (Supersession | undefined)[] = []
      const { person } = await sentOnce(answers, recorded, reads, [], quotes)
      await readOnce(reads)
      recorded.revision = '4'
      await person.click(await release())
      await waitFor(() => {
        expect(quotes).toHaveLength(2)
      })
      expect(quotes[1]).toEqual({ action_id: ACTION, revision: '4' })
      expect(await screen.findByText('Applied', {}, { timeout: 3_000 })).toBeInTheDocument()
    })

    it('sends nothing and shows the result when the record has become applied', async () => {
      const recorded: Recorded = { state: 'unknown', revision: '3' }
      const reads: string[] = []
      const sent: unknown[] = []
      const { person } = await sentOnce(answers, recorded, reads, sent)
      await readOnce(reads)
      recorded.state = 'applied'
      recorded.revision = '5'
      await person.click(await release())
      expect(await screen.findByText('Applied', {}, { timeout: 3_000 })).toBeInTheDocument()
      await flush()
      expect(sent).toHaveLength(1)
      expect(screen.getByLabelText('Message this session')).toHaveValue('')
    })

    it('sends nothing, and gives the text back, when the record has become refused', async () => {
      const recorded: Recorded = { state: 'unknown', revision: '3' }
      const reads: string[] = []
      const sent: unknown[] = []
      const { person } = await sentOnce(answers, recorded, reads, sent)
      await readOnce(reads)
      recorded.state = 'refused'
      recorded.revision = '5'
      await person.click(await release())
      expect(await screen.findByText('Refused by the host', {}, { timeout: 3_000 })).toBeInTheDocument()
      await flush()
      expect(sent).toHaveLength(1)
      expect(screen.getByLabelText('Message this session')).toHaveValue('run the migration')
    })

    it('names what it read last when the host cannot be asked at the press', async () => {
      const recorded: Recorded = { state: 'unknown', revision: '3' }
      const reads: string[] = []
      const quotes: (Supersession | undefined)[] = []
      const { person } = await sentOnce(answers, recorded, reads, [], quotes)
      await readOnce(reads)
      recorded.unreadable = true
      await person.click(await release())
      await waitFor(() => {
        expect(quotes).toHaveLength(2)
      })
      expect(quotes[1]).toEqual({ action_id: ACTION, revision: '3' })
    })
  })

  it('names nothing when the earlier record could not be read', async () => {
    const recorded: Recorded = { state: 'unknown', unreadable: true }
    const quotes: (Supersession | undefined)[] = []
    const second: Settled<AgentMutationResult> = {
      receipt: receiptAt('dispatching', ANOTHER_ACTION),
      value: null,
      action_id: ANOTHER_ACTION
    }
    const { person } = await sentOnce(
      (attempt) => (attempt === 1 ? UNCONFIRMED : second),
      recorded,
      [],
      [],
      quotes
    )
    await person.click(await screen.findByRole('button', { name: 'I checked; send anyway' }))
    await waitFor(() => {
      expect(quotes).toHaveLength(2)
    })
    expect(quotes[1]).toBeUndefined()
  })

  it('names the action the host named when it refused the quote of another that the page picked', async () => {
    const unconfirmed = (action: string): Settled<AgentMutationResult> => ({
      receipt: null,
      value: null,
      action_id: action
    })
    const refused = Object.assign(new Error('the quote was not the newest'), {
      code: 'DRAFT_CONFLICT',
      message: `DRAFT_CONFLICT: the uncertain outcome of this subject is action ${ACTION}, not ${ANOTHER_ACTION}`,
      user_action: 'retry'
    })
    const recorded: Recorded = { state: 'unknown', revision: '3' }
    const reads: string[] = []
    const quotes: (Supersession | undefined)[] = []
    const { person } = await sentOnce(
      (attempt) =>
        attempt === 1
          ? unconfirmed(ACTION)
          : attempt === 2
            ? unconfirmed(ANOTHER_ACTION)
            : attempt === 3
              ? refused
              : unconfirmed(ACTION),
      recorded,
      reads,
      [],
      quotes
    )
    await waitFor(
      () => {
        expect(reads).toContain(ACTION)
      },
      { timeout: 3_000 }
    )
    await flush()
    await person.click(await screen.findByRole('button', { name: 'I checked; send anyway' }))
    await waitFor(() => {
      expect(quotes).toHaveLength(2)
    })
    await waitFor(
      () => {
        expect(reads).toContain(ANOTHER_ACTION)
      },
      { timeout: 3_000 }
    )
    await flush()

    // The page quotes the later identifier, and the host refuses it, naming the other.
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'I checked; send anyway' })).toBeEnabled()
    })
    await person.click(screen.getByRole('button', { name: 'I checked; send anyway' }))
    await waitFor(() => {
      expect(quotes).toHaveLength(3)
    })
    expect(quotes[2]).toEqual({ action_id: ANOTHER_ACTION, revision: '3' })
    await screen.findAllByText(/the uncertain outcome of this subject is action/)

    // The next press quotes the action the refusal named.
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'I checked; send anyway' })).toBeEnabled()
    })
    await person.click(screen.getByRole('button', { name: 'I checked; send anyway' }))
    await waitFor(() => {
      expect(quotes).toHaveLength(4)
    })
    expect(quotes[3]).toEqual({ action_id: ACTION, revision: '3' })
  })

  it('quotes a prompt made after the refusal when the window\'s clock has stepped back since', async () => {
    const unconfirmed = (action: string): Settled<AgentMutationResult> => ({
      receipt: null,
      value: null,
      action_id: action
    })
    const refused = Object.assign(new Error('the quote was not the newest'), {
      code: 'DRAFT_CONFLICT',
      message: `DRAFT_CONFLICT: the uncertain outcome of this subject is action ${ACTION}, not ${ANOTHER_ACTION}`,
      user_action: 'retry'
    })
    const recorded: Recorded = { state: 'unknown', revision: '3' }
    const reads: string[] = []
    const quotes: (Supersession | undefined)[] = []
    const real = Date.now.bind(Date)
    let stepped = 0
    const clock = vi.spyOn(Date, 'now').mockImplementation(() => real() - stepped)
    try {
      const { person } = await sentOnce(
        (attempt) =>
          attempt === 1
            ? unconfirmed(ACTION)
            : attempt === 2
              ? unconfirmed(ANOTHER_ACTION)
              : attempt === 3
                ? refused
                : unconfirmed(THIRD_ACTION),
        recorded,
        reads,
        [],
        quotes
      )
      await waitFor(
        () => {
          expect(reads).toContain(ACTION)
        },
        { timeout: 3_000 }
      )
      await flush()
      await person.click(await screen.findByRole('button', { name: 'I checked; send anyway' }))
      await waitFor(() => {
        expect(quotes).toHaveLength(2)
      })
      await waitFor(
        () => {
          expect(reads).toContain(ANOTHER_ACTION)
        },
        { timeout: 3_000 }
      )
      await flush()
      await waitFor(() => {
        expect(screen.getByRole('button', { name: 'I checked; send anyway' })).toBeEnabled()
      })
      await person.click(screen.getByRole('button', { name: 'I checked; send anyway' }))
      await waitFor(() => {
        expect(quotes).toHaveLength(3)
      })
      await screen.findAllByText(/the uncertain outcome of this subject is action/)

      stepped = STEP_BACK_MS
      await waitFor(() => {
        expect(screen.getByRole('button', { name: 'I checked; send anyway' })).toBeEnabled()
      })
      await person.click(screen.getByRole('button', { name: 'I checked; send anyway' }))
      await waitFor(() => {
        expect(quotes).toHaveLength(4)
      })
      expect(quotes[3]?.action_id).toBe(ACTION)
      await waitFor(
        () => {
          expect(reads).toContain(THIRD_ACTION)
        },
        { timeout: 3_000 }
      )
      await flush()
      await waitFor(() => {
        expect(screen.getByRole('button', { name: 'I checked; send anyway' })).toBeEnabled()
      })
      await person.click(screen.getByRole('button', { name: 'I checked; send anyway' }))
      await waitFor(() => {
        expect(quotes).toHaveLength(5)
      })
      expect(quotes[4]).toEqual({ action_id: THIRD_ACTION, revision: '3' })
    } finally {
      clock.mockRestore()
    }
  })

  it('is not offered a way past while the host merely has the action', async () => {
    const recorded = { state: 'dispatching' as Receipt['state'] }
    await sentOnce(WITH_THE_HOST, recorded)
    await waitFor(() => {
      expect(screen.getByLabelText('Message this session')).toHaveValue('')
    })
    expect(screen.queryByRole('button', { name: 'I checked; send anyway' })).toBeNull()
  })

  it('does not put the text back when the second send is refused after the first was applied', async () => {
    const recorded: Recorded = { state: 'unknown', byAction: {} }
    const device = new FakeDraftStore()
    const host = fakeHost({ drafts: device })
    let refuse: (failure: unknown) => void = () => undefined
    const second = new Promise<Settled<AgentMutationResult>>((_, reject) => {
      refuse = reject
    })
    let attempts = 0
    const port: HostPort = {
      ...answering(host.port, UNCONFIRMED, recorded),
      composerSubmit: () => {
        attempts += 1
        return attempts === 1 ? Promise.resolve(UNCONFIRMED) : second
      }
    }
    render(
      <AppProvider port={port}>
        <MobileApp surface="ios" storage={null} />
      </AppProvider>
    )
    const person = userEvent.setup()
    await person.click(await screen.findByRole('button', { name: /^Sessions/ }))
    await person.click(await screen.findByRole('button', { name: /Session 1/ }))
    await person.type(await screen.findByLabelText('Message this session'), 'run the migration')
    await person.click(screen.getByRole('button', { name: 'Send' }))
    await person.click(await screen.findByRole('button', { name: 'I checked; send anyway' }))
    await waitFor(() => {
      expect(attempts).toBe(2)
    })

    // The host says the first was applied, while the second is still on its way. The page is shown
    // again, which reads the host's record at once instead of after the wait.
    recorded.byAction = { [ACTION]: 'applied' }
    act(() => {
      document.dispatchEvent(new Event('visibilitychange'))
    })
    await waitFor(() => {
      expect(screen.getByLabelText('Message this session')).toHaveValue('')
    })
    await act(async () => {
      refuse({ code: 'REFUSED', message: 'The host refused it.' })
      await Promise.resolve()
    })
    await flush()

    // The words were done once: nothing puts them back for a third send.
    expect(screen.getByLabelText('Message this session')).toHaveValue('')
    expect(device.all()).toEqual([])
  })

  describe('when the application starts again after a prompt nobody knew the end of', () => {
    /** One phone's storage and device store, and the person, over any number of runs. */
    function runs() {
      const storage = fakeStorage()
      const device = new FakeDraftStore()
      const person = userEvent.setup()
      const run = (answer: Settled<AgentMutationResult> | Promise<Settled<AgentMutationResult>> | 'never', recorded: Recorded) => {
        const host = fakeHost({ drafts: device })
        const waiting = answer === 'never' || answer instanceof Promise
        const port = answering(host.port, waiting ? UNCONFIRMED : answer, recorded)
        return render(
          <AppProvider
            port={
              waiting
                ? { ...port, composerSubmit: () => (answer === 'never' ? new Promise(() => undefined) : answer) }
                : port
            }
          >
            <MobileApp surface="ios" storage={storage} />
          </AppProvider>
        )
      }
      const open = async () => {
        await person.click(await screen.findByRole('button', { name: /^Sessions/ }))
        await person.click(await screen.findByRole('button', { name: /Session 1/ }))
        return await screen.findByLabelText('Message this session')
      }
      return { device, person, run, open }
    }

    it('keeps the session held, and offers the way past, for a prompt that was on its way when it ended', async () => {
      const { person, run, open } = runs()
      // The first run presses Send and the application ends before the host answers.
      const first = run('never', { state: 'unknown' })
      await person.type(await open(), 'run the migration')
      await person.click(screen.getByRole('button', { name: 'Send' }))
      first.unmount()

      run(UNCONFIRMED, { state: 'unknown' })
      await open()

      // The request may have left, so it is an action nobody knows the end of, which a person who
      // checked can send past.
      expect(await screen.findByRole('button', { name: 'I checked; send anyway' })).toBeInTheDocument()
      expect(screen.getByRole('button', { name: 'Send' })).toBeDisabled()
    })

    it('does not clear a newer draft that holds the same words', async () => {
      const { device, person, run, open } = runs()
      const first = run(UNCONFIRMED, { state: 'unknown' })
      const field = await open()
      await person.type(field, 'continue')
      await person.click(screen.getByRole('button', { name: 'Send' }))
      await screen.findByText(/no confirmed outcome yet/)
      // The person throws the returned text away and writes the same words again: a draft of its own.
      await person.clear(screen.getByLabelText('Message this session'))
      await person.type(screen.getByLabelText('Message this session'), 'continue')
      await waitFor(() => {
        expect(device.all().map((draft) => draft.text)).toEqual(['continue'])
      })
      first.unmount()

      run(UNCONFIRMED, { state: 'applied' })
      await open()
      await waitFor(
        () => {
          expect(screen.queryByText(/no confirmed outcome yet/)).toBeNull()
        },
        { timeout: 3_000 }
      )
      // The earlier prompt was applied; the newer draft is not that prompt's.
      expect(screen.getByLabelText('Message this session')).toHaveValue('continue')
      expect(device.all().map((draft) => draft.text)).toEqual(['continue'])
    })

    it('removes the draft the text was stored under after the send ended, once the host says it was applied', async () => {
      const { device, person, run, open } = runs()
      // The store cannot be used while the prompt is on its way, so nothing stores its text.
      device.breakOpening()
      let answer: (value: Settled<AgentMutationResult>) => void = () => undefined
      const host = new Promise<Settled<AgentMutationResult>>((resolve) => {
        answer = resolve
      })
      const first = run(host, { state: 'unknown' })
      await person.type(await open(), 'run the migration')
      await person.click(screen.getByRole('button', { name: 'Send' }))
      // The person writes something else before the host answers, so the prompt's text cannot go back
      // to the composer when the send ends.
      await person.clear(screen.getByLabelText('Message this session'))
      await person.type(screen.getByLabelText('Message this session'), 'something newer')
      await act(async () => {
        answer(UNCONFIRMED)
        await Promise.resolve()
      })
      await screen.findByText(/no confirmed outcome yet/)
      // The store is mended and read again, and keeps the prompt's text apart from the composer's.
      device.mendOpening()
      await person.click(await screen.findByTestId('drafts-retry'))
      await waitFor(() => {
        expect(device.all().map((draft) => draft.text).sort()).toEqual(['run the migration', 'something newer'])
      })
      first.unmount()

      run(UNCONFIRMED, { state: 'applied' })
      await open()

      // The draft the phone was told of is the one that goes, and the newer text stays.
      await waitFor(
        () => {
          expect(device.all().map((draft) => draft.text)).toEqual(['something newer'])
        },
        { timeout: 3_000 }
      )
    })

    it('removes the text of a prompt, once the host says it was applied', async () => {
      const { device, person, run, open } = runs()
      // The first run sends a prompt and is never told what became of it, and then ends.
      const first = run(UNCONFIRMED, { state: 'unknown' })
      await person.type(await open(), 'run the migration')
      await person.click(screen.getByRole('button', { name: 'Send' }))
      await screen.findByText(/no confirmed outcome yet/)
      first.unmount()

      // The next run finds the text under its stored draft, held: nobody knows yet what became of it.
      run(UNCONFIRMED, { state: 'applied' })
      expect(await open()).toBeInTheDocument()

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
