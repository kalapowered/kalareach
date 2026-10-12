/**
 * How often the host's record of an action is read while the action has no outcome.
 *
 * An action nobody has heard the end of can stay that way for as long as the host takes, so the
 * interface does not ask at a fixed pace for all of that time: each read that finds nothing new
 * waits longer than the one before, up to a ceiling, and a person who opens the session again is
 * answered at once and gets the quick pace back. The clock here is the test's own.
 */

import { act, cleanup, render } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import type { Receipt } from '@kalareach/protocol'

import { AppProvider } from '../src/app/state'
import { useReceiptReads } from '../src/app/receipts'
import { fakeHost } from '../src/host/fake'
import type { Submission } from '../src/model/receipts'

const SESSION = '8a7b6c50-22bb-4c3d-8e4f-000000000101'
const ACTION = '00000000-0000-4000-8000-00000000abcd'

/** An action the host never confirmed. */
const UNKNOWN: Submission = {
  localId: 'local-1',
  actionId: ACTION,
  label: 'run it',
  text: 'run it',
  state: 'unknown',
  createdAtMs: 0,
  error: null
}

/** A record that says nothing new: the host still does not know either. */
const NOTHING_NEW: Receipt = {
  action_id: ACTION,
  actor_id: 'owner:local',
  error: null,
  method: 'agent.prompt.submit',
  method_version: 1,
  payload_digest: '0'.repeat(64),
  reason: null,
  revision: '1',
  state: 'unknown',
  updated_at_ms: '0',
  accepted_deadline_ms: null
}

/** Sets what the page says about being shown, and tells whoever listens. */
function showPage(state: 'visible' | 'hidden'): void {
  Object.defineProperty(document, 'visibilityState', { configurable: true, value: state })
  document.dispatchEvent(new Event('visibilitychange'))
}

function Reads({ submissions }: { readonly submissions: readonly Submission[] }) {
  useReceiptReads({ sessionId: SESSION, connected: true, submissions, onReceipt: () => undefined })
  return null
}

describe('the reads of the host’s record of an action', () => {
  /** When each read of the record began, in the test's own clock. */
  const began: number[] = []
  let start = 0

  /** Mounts a view that reads the record of one action. */
  function open() {
    const host = fakeHost()
    return render(
      <AppProvider
        port={{
          ...host.port,
          actionRead: () => {
            began.push(Date.now() - start)
            return Promise.resolve({ receipt: NOTHING_NEW, result: null })
          }
        }}
      >
        <Reads submissions={[UNKNOWN]} />
      </AppProvider>
    )
  }

  /** Lets the clock run on for `ms`, with every answer and timer along the way handled. */
  async function runFor(ms: number): Promise<void> {
    await act(async () => {
      await vi.advanceTimersByTimeAsync(ms)
    })
  }

  beforeEach(() => {
    vi.useFakeTimers()
    start = Date.now()
    began.length = 0
  })

  afterEach(() => {
    cleanup()
    showPage('visible')
    vi.useRealTimers()
  })

  it('wait longer after each read that finds nothing new, up to a ceiling', async () => {
    open()
    await runFor(200_000)

    // The first read is at once, then a pace that doubles from four seconds to a minute.
    expect(began.slice(0, 7)).toEqual([0, 4_000, 12_000, 28_000, 60_000, 120_000, 180_000])
  })

  it('are quick again when the person opens the session', async () => {
    const first = open()
    await runFor(30_000)
    // Four reads so far, the last of them 16 seconds after the one before.
    expect(began).toEqual([0, 4_000, 12_000, 28_000])

    // Opening the session again is a new view: it reads at once, and then at the first pace.
    first.unmount()
    const at = Date.now() - start
    open()
    await runFor(13_000)
    expect(began.slice(4)).toEqual([at, at + 4_000, at + 12_000])
  })

  it('are quick again when the page is shown after it was hidden', async () => {
    open()
    await runFor(30_000)
    expect(began).toEqual([0, 4_000, 12_000, 28_000])

    showPage('hidden')
    await runFor(60_000)
    const reading = began.length
    showPage('visible')
    await runFor(13_000)
    const at = 90_000
    expect(began.slice(reading)).toEqual([at, at + 4_000, at + 12_000])
  })
})
