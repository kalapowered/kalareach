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
import { applyReceipt, type Submission } from '../src/model/receipts'
import { fakeHost } from '../src/host/fake'
import { FakeDraftStore } from '../src/host/fake-drafts'
import type { HostPort, Settled } from '../src/host/port'
import { MobileApp } from '../src/mobile/MobileApp'

const SESSION_MAIN = '8a7b6c50-22bb-4c3d-8e4f-000000000101'
const ACTION = '00000000-0000-4000-8000-00000000abcd'

afterEach(cleanup)

/** A receipt of the prompt, at the state the host last recorded. */
function receiptAt(state: Receipt['state']): Receipt {
  return {
    action_id: ACTION,
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

/** A port whose prompts are answered with `answer`, and whose record of the action is `recorded`. */
function answering(
  port: HostPort,
  answer: Settled<AgentMutationResult>,
  recorded: { state: Receipt['state'] },
  reads: string[] = [],
  sent: unknown[] = []
): HostPort {
  return {
    ...port,
    composerSubmit: (params) => {
      sent.push(params)
      return Promise.resolve(answer)
    },
    actionRead: (params) => {
      reads.push(params.action_id)
      return Promise.resolve({ receipt: receiptAt(recorded.state), result: null })
    }
  }
}

describe('on the desktop', () => {
  /** The desktop's conversation over a device's drafts, with the person's text sent once. */
  async function sentOnce(
    answer: Settled<AgentMutationResult>,
    recorded: { state: Receipt['state'] },
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
    expect(screen.getByTestId('composer-send')).toBeDisabled()
    expect(screen.getByTestId('composer-reason')).toHaveTextContent(/no confirmed outcome yet/)
  })

  it('keeps holding an action the host still records as accepted, until the record says applied', async () => {
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
    answer: Settled<AgentMutationResult>,
    recorded: { state: Receipt['state'] },
    reads: string[] = []
  ) {
    const device = new FakeDraftStore()
    const host = fakeHost({ drafts: device })
    render(
      <AppProvider port={answering(host.port, answer, recorded, reads)}>
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

describe('what a receipt that arrives later does to a submission', () => {
  const sent = (state: 'sent' | 'unknown' | 'applied', revision: string): Submission => ({
    localId: 'local-1',
    actionId: ACTION,
    label: 'run it',
    text: 'run it',
    state,
    createdAtMs: 0,
    error: null,
    revision
  })
  const record = (state: Receipt['state'], revision: string): Receipt => ({
    ...receiptAt(state),
    revision
  })

  it('never goes back from a final state', () => {
    const done = sent('applied', '4')
    expect(applyReceipt(done, record('unknown', '5'))).toBe(done)
    expect(applyReceipt(done, record('refused', '5'))).toBe(done)
  })

  it('never takes a receipt older than the one it has, whichever read or event arrives last', () => {
    const newer = sent('sent', '3')
    expect(applyReceipt(newer, record('accepted', '2'))).toBe(newer)
    expect(applyReceipt(newer, record('applied', '4')).state).toBe('applied')
  })

  it('stays unknown until the host says applied or refused', () => {
    const nobody = sent('unknown', '1')
    expect(applyReceipt(nobody, record('dispatching', '2'))).toBe(nobody)
    expect(applyReceipt(nobody, record('applied', '3')).state).toBe('applied')
    expect(applyReceipt(nobody, record('refused', '3')).state).toBe('refused')
  })
})
