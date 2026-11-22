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

  it('takes a read asked for meanwhile as the further read that the read makes, and keeps a later one', async () => {
    const waiting: (() => void)[] = []
    let started = 0
    let takeAskedFor: () => void = () => undefined
    const answer = async () => {
      waiting.shift()?.()
      await Promise.resolve()
      await Promise.resolve()
    }
    const cadence = readOnCadence((take) => {
      started += 1
      takeAskedFor = take
      return new Promise<void>((resolve) => {
        waiting.push(resolve)
      })
    }, 1_000)
    cadence.now()
    cadence.now()
    // The read makes its further read, which is the one that was asked for: none runs after it.
    takeAskedFor()
    await answer()
    expect(started).toBe(1)
    await vi.advanceTimersByTimeAsync(1_000)
    expect(started).toBe(2)
    // A read asked for after the call is not that one.
    takeAskedFor()
    cadence.now()
    await answer()
    expect(started).toBe(3)
    cadence.stop()
  })

  it('takes a wake asked for meanwhile as the further read that the read makes, and keeps a later one', async () => {
    const waiting: (() => void)[] = []
    let started = 0
    let takeAskedFor: () => void = () => undefined
    const answer = async () => {
      waiting.shift()?.()
      await Promise.resolve()
      await Promise.resolve()
    }
    const cadence = readOnCadence(
      (take) => {
        started += 1
        takeAskedFor = take
        return new Promise<void>((resolve) => {
          waiting.push(resolve)
        })
      },
      1_000,
      250
    )
    cadence.now()
    cadence.soon()
    // The read makes its further read, which is the one the wake asked for: none runs after it.
    takeAskedFor()
    await answer()
    await vi.advanceTimersByTimeAsync(300)
    expect(started).toBe(1)
    // The cadence still reads a cadence after the answer.
    await vi.advanceTimersByTimeAsync(700)
    expect(started).toBe(2)
    // A wake asked for after the call is not that read.
    takeAskedFor()
    cadence.soon()
    await answer()
    await vi.advanceTimersByTimeAsync(250)
    expect(started).toBe(3)
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

  it('a_state_the_view_publishes_wakes_the_read: starts it now, where the cadence would wait', async () => {
    const held = reads()
    const cadence = readOnCadence(held.read, 2_000, 250)
    cadence.now()
    await held.answer()
    await vi.advanceTimersByTimeAsync(250)
    expect(held.started()).toBe(1)
    // The wake does not wait out the cadence: the last read started a gap ago.
    cadence.soon()
    expect(held.started()).toBe(2)
    cadence.stop()
  })

  it('no_more_than_one_wake_read_starts_in_each_250_ms', async () => {
    const held = reads()
    const cadence = readOnCadence(held.read, 2_000, 250)
    cadence.now()
    await held.answer()
    // Output arrives all the while: each wake asks, and the gap decides.
    for (let each = 0; each < 20; each += 1) {
      await vi.advanceTimersByTimeAsync(25)
      cadence.soon()
    }
    // The first wake waited out the gap and started one read; the rest arrived while it was out.
    expect(held.started()).toBe(2)
    // They cost one more read, started once that one answers and a gap has passed, not one each.
    await held.answer()
    expect(held.started()).toBe(3)
    await vi.advanceTimersByTimeAsync(100)
    expect(held.started()).toBe(3)
    cadence.stop()
  })

  it('states_that_arrive_while_a_read_is_out_cost_one_more_read_and_not_one_each', async () => {
    const held = reads()
    const cadence = readOnCadence(held.read, 2_000, 250)
    cadence.now()
    for (let each = 0; each < 10; each += 1) cadence.soon()
    expect(held.started()).toBe(1)
    await vi.advanceTimersByTimeAsync(300)
    await held.answer()
    expect(held.started()).toBe(2)
    await held.answer()
    await vi.advanceTimersByTimeAsync(249)
    expect(held.started()).toBe(2)
    cadence.stop()
  })

  it('a_hidden_page_wakes_no_read', async () => {
    const held = reads()
    const cadence = readOnCadence(held.read, 2_000, 250)
    cadence.now()
    await held.answer()
    showPage('hidden')
    await vi.advanceTimersByTimeAsync(1_000)
    cadence.soon()
    await vi.advanceTimersByTimeAsync(1_000)
    expect(held.started()).toBe(1)
    showPage('visible')
    expect(held.started()).toBe(2)
    cadence.stop()
  })

  it('reads_nothing_on_a_wake_before_the_first_read_is_asked_for', async () => {
    const held = reads()
    const cadence = readOnCadence(held.read, 2_000, 250)
    cadence.soon()
    await vi.advanceTimersByTimeAsync(5_000)
    expect(held.started()).toBe(0)
    cadence.stop()
  })

  it('a_wake_every_250_ms_postpones_the_cadence_it_wakes_and_never_another_cadence', async () => {
    // The surface is woken by output every 250 ms for ever; the list has a cadence of its own that
    // no wake reaches, so its deadline is its last read plus a cadence whatever the surface does.
    const surface = reads()
    const list = reads()
    const surfaceCadence = readOnCadence(surface.read, 2_000, 250)
    const listCadence = readOnCadence(list.read, 2_000)
    surfaceCadence.now()
    listCadence.now()
    await surface.answer()
    await list.answer()
    for (let each = 0; each < 7; each += 1) {
      await vi.advanceTimersByTimeAsync(250)
      surfaceCadence.soon()
      await surface.answer()
    }
    expect(list.started()).toBe(1)
    await vi.advanceTimersByTimeAsync(250)
    expect(list.started()).toBe(2)
    surfaceCadence.stop()
    listCadence.stop()
  })
})
