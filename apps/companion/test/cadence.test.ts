/**
 * Reading again while a view is shown: on a cadence, at once when the page is shown again, and
 * never twice at once.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { readOnCadence } from '../src/app/cadence'

/** A read the test answers by hand, and how many were started. */
function reads(): {
  readonly read: () => Promise<void>
  readonly started: () => number
  readonly answer: () => Promise<void>
} {
  const waiting: (() => void)[] = []
  let started = 0
  return {
    read: () => {
      started += 1
      return new Promise<void>((resolve) => {
        waiting.push(resolve)
      })
    },
    started: () => started,
    answer: async () => {
      waiting.shift()?.()
      // Lets the settled read's own handlers run.
      await Promise.resolve()
      await Promise.resolve()
    }
  }
}

/** Sets what the page says about being shown, and tells whoever listens. */
function showPage(state: 'visible' | 'hidden'): void {
  Object.defineProperty(document, 'visibilityState', { configurable: true, value: state })
  document.dispatchEvent(new Event('visibilitychange'))
}

describe('reading on a cadence', () => {
  beforeEach(() => {
    vi.useFakeTimers()
  })

  afterEach(() => {
    showPage('visible')
    vi.useRealTimers()
  })

  it('reads nothing until it is first asked, then again a cadence after each answer', async () => {
    const held = reads()
    const cadence = readOnCadence(held.read, 1_000)
    await vi.advanceTimersByTimeAsync(5_000)
    expect(held.started()).toBe(0)

    cadence.now()
    expect(held.started()).toBe(1)
    // A slow answer holds the next read back: it starts a cadence after the answer, not before.
    await vi.advanceTimersByTimeAsync(3_000)
    expect(held.started()).toBe(1)
    await held.answer()
    await vi.advanceTimersByTimeAsync(999)
    expect(held.started()).toBe(1)
    await vi.advanceTimersByTimeAsync(1)
    expect(held.started()).toBe(2)
    cadence.stop()
  })

  it('runs a read asked for while one is on its way once that one has answered, and only one', async () => {
    const held = reads()
    const cadence = readOnCadence(held.read, 1_000)
    cadence.now()
    cadence.now()
    cadence.now()
    expect(held.started()).toBe(1)
    await held.answer()
    expect(held.started()).toBe(2)
    await held.answer()
    await vi.advanceTimersByTimeAsync(999)
    expect(held.started()).toBe(2)
    cadence.stop()
  })

  it('reads nothing while the page is hidden, and reads at once when it is shown again', async () => {
    const held = reads()
    const cadence = readOnCadence(held.read, 1_000)
    cadence.now()
    await held.answer()

    showPage('hidden')
    await vi.advanceTimersByTimeAsync(10_000)
    expect(held.started()).toBe(1)

    showPage('visible')
    expect(held.started()).toBe(2)
    cadence.stop()
  })

  it('reads nothing once stopped, and a read on its way starts no other', async () => {
    const held = reads()
    const cadence = readOnCadence(held.read, 1_000)
    cadence.now()
    cadence.now()
    cadence.stop()
    await held.answer()
    await vi.advanceTimersByTimeAsync(10_000)
    showPage('visible')
    cadence.now()
    expect(held.started()).toBe(1)
  })

  it('keeps reading after a read that failed', async () => {
    let started = 0
    const cadence = readOnCadence(() => {
      started += 1
      return Promise.reject(new Error('refused'))
    }, 1_000)
    cadence.now()
    await vi.advanceTimersByTimeAsync(1_000)
    await vi.advanceTimersByTimeAsync(1_000)
    expect(started).toBe(3)
    cadence.stop()
  })
})
