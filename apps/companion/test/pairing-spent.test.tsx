/**
 * What the pairing screen says when an attempt failed after the host had locked its invitation to
 * it. Native code marks such a failure, and only for an attempt made through a rendezvous service;
 * the page then tells a person that the invitation can no longer be used and offers to start again.
 * An attempt with no mark, and a direct invitation, keep the words and the action they had.
 *
 * The scripted host stands in for native code: it publishes the failure native code sends, and what
 * is drawn is what the person reads.
 */

import { describe, expect, it } from 'vitest'
import { act, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { App } from '../src/App'
import { AppProvider } from '../src/app/state'
import { fakeHost, type FakeHostControls } from '../src/host/fake'
import type { AttemptState, PairingFailure } from '../src/host/port'

const CODE = 'AbCd-EfG-H23'

function start(): { controls: FakeHostControls } {
  const { port, controls } = fakeHost()
  render(
    <AppProvider port={port} initialPlace={{ view: 'pairing' }}>
      <App />
    </AppProvider>
  )
  return { controls }
}

function attempt(controls: FakeHostControls, state: AttemptState): void {
  act(() => {
    controls.setPairing({ state })
  })
}

function ended(failure: PairingFailure, mode: 'code' | 'direct' = 'code'): AttemptState {
  return { state: 'ended', failure, mode, service: null }
}

/** The failures of the managed relay and of an unreachable host, with the mark or without it. */
const capacity = (marked: boolean): PairingFailure => ({
  kind: 'relay_capacity',
  tries_left: null,
  retry_after_seconds: 90,
  ...(marked ? { invitation_spent: true as const } : {})
})
const fault = (marked: boolean): PairingFailure => ({
  kind: 'relay_fault',
  tries_left: null,
  retry_after_seconds: 600,
  ...(marked ? { invitation_spent: true as const } : {})
})
const unreachable = (marked: boolean): PairingFailure => ({
  kind: 'host_unreachable',
  tries_left: null,
  ...(marked ? { invitation_spent: true as const } : {})
})

/** The words a failure had before the mark, which an attempt that says nothing of one keeps. */
const OLD = {
  relay_capacity:
    "The managed relay could not take this pairing now. Try again in about 2 minutes, or bring this device onto the host's network.",
  relay_fault:
    "The managed relay service could not admit this pairing now. This is not a fault of the host. Try again in about 10 minutes, or bring this device onto the host's network.",
  host_unreachable:
    "The host could not be reached. Check that this device is on the host's network, or that the host is online."
} as const

/** The ruled words for a failure that came after the host locked the invitation. */
const SPENT = {
  relay_capacity:
    "The managed relay could not take this pairing now, and this invitation can no longer be used. Ask the host for a new invitation in about 2 minutes, or bring this device onto the host's network and ask for one now.",
  relay_fault:
    "The managed relay service could not admit this pairing now, and this invitation can no longer be used. This is not a fault of the host. Ask the host for a new invitation in about 10 minutes, or bring this device onto the host's network and ask for one now.",
  host_unreachable:
    "The host could not be reached, and this invitation can no longer be used. Check that this device is on the host's network, or that the host is online, then ask the host for a new invitation."
} as const

const KINDS = [
  ['relay_capacity', capacity, 'capacity'],
  ['relay_fault', fault, 'fault'],
  ['host_unreachable', unreachable, 'unreachable']
] as const

describe('a pairing that failed after the host locked its invitation', () => {
  // The cell for a code, typed or read, that failed on the way to the host: the host consumes the
  // invitation as expired, so a new one is needed, and the action starts again.
  it.each(KINDS)('says a new invitation is needed after %s, and offers to start again', async (kind, make) => {
    const { controls } = start()
    await screen.findByLabelText('Pairing code')
    attempt(controls, ended(make(true)))
    expect((await screen.findByTestId('failure-sentence')).textContent).toBe(SPENT[kind])
    expect(screen.getByTestId('failure-action').textContent).toBe('Start again')
  })

  // The same kinds from an attempt that was not marked: a restarted device that cannot reach the
  // host, or a host that committed the device and could not be reached as it. They keep today's
  // words and action.
  it.each(KINDS)('keeps the old words and action for %s when the failure is not marked', async (kind, make) => {
    const { controls } = start()
    await screen.findByLabelText('Pairing code')
    attempt(controls, ended(make(false)))
    expect((await screen.findByTestId('failure-sentence')).textContent).toBe(OLD[kind])
    expect(screen.getByTestId('failure-action').textContent).toBe('Try again')
  })

  // A direct invitation whose dial was lost was never seen by the host, and is brought in again.
  it.each(KINDS)('keeps the old words and "Paste again" for %s in a direct attempt', async (kind, make) => {
    const { controls } = start()
    await screen.findByLabelText('Pairing code')
    for (const marked of [false, true]) {
      attempt(controls, ended(make(marked), 'direct'))
      expect((await screen.findByTestId('failure-sentence')).textContent).toBe(OLD[kind])
      expect(screen.getByTestId('failure-action').textContent).toBe('Paste again')
    }
  })

  // A kind that the mark does not change is not changed by it.
  it('leaves the words and "Try again" of a failure that the mark does not change as they are', async () => {
    const { controls } = start()
    await screen.findByLabelText('Pairing code')
    attempt(controls, ended({ kind: 'did_not_finish', tries_left: null, invitation_spent: true }))
    expect((await screen.findByTestId('failure-sentence')).textContent).toBe(
      'Pairing did not finish. Try again, or ask the host for a new invitation. If the host still lists this device as paired, a new invitation works only after that pairing has ended.'
    )
    expect(screen.getByTestId('failure-action').textContent).toBe('Try again')
  })

  // The exchange that stalled may have reached the host or not, so it says both.
  it('says that a stalled exchange may need a new invitation, and keeps "Try again"', async () => {
    const { controls } = start()
    await screen.findByLabelText('Pairing code')
    attempt(controls, ended({ kind: 'timed_out', tries_left: null }))
    expect((await screen.findByTestId('failure-sentence')).textContent).toBe(
      'The host did not finish the exchange in time. Try again, or ask the host for a new invitation.'
    )
    expect(screen.getByTestId('failure-action').textContent).toBe('Try again')
  })

  // A restarted device that cannot reach the host to learn whether the owner decided.
  it('says what is unknown when a resumed attempt cannot ask the host', async () => {
    const { controls } = start()
    await screen.findByLabelText('Pairing code')
    attempt(controls, ended({ kind: 'approval_unknown', tries_left: null }))
    expect((await screen.findByTestId('failure-sentence')).textContent).toBe(
      'The host may have approved this device while KalaReach could not ask, but KalaReach cannot confirm that. Ask the owner to check the host.'
    )
    expect(screen.getByTestId('failure-action').textContent).toBe('Done')
  })

  // The typed code is the one secret the page holds: it leaves the field with the sentence, so the
  // spent code is not offered again, and it stays when the failure is not marked.
  it('lets the typed code go with the sentence, and keeps it when nothing says it was spent', async () => {
    const { controls } = start()
    const field = async () => await screen.findByLabelText<HTMLInputElement>('Pairing code')
    const typed = async () => {
      await userEvent.clear(await field())
      await userEvent.type(await field(), CODE)
    }
    for (const [kind, make] of KINDS) {
      await typed()
      attempt(controls, ended(make(true)))
      await userEvent.click(await screen.findByTestId('failure-action'))
      expect((await field()).value, kind).toBe('')

      await typed()
      attempt(controls, ended(make(false)))
      await userEvent.click(await screen.findByTestId('failure-action'))
      expect((await field()).value, kind).toBe(CODE)
    }
  })
})
