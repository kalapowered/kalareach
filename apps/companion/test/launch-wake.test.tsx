/**
 * What wakes the launch surface's read, what darkens its buttons, and when the saved launch commands
 * are read (KR-REQ-13.11).
 *
 * The hook is run with reads the test answers by hand and a clock the test moves, so each case
 * decides by call order and the fake clock and never by waiting: a state the view publishes wakes the
 * surface's read, an input the person sends darkens the buttons in its own frame, and the list of
 * saved commands has a deadline of its own that no wake of the surface reaches.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, renderHook } from '@testing-library/react'

import {
  LAUNCH_SURFACE_CADENCE_MS,
  useLaunchSurface,
  type InputCounts,
  type LaunchSurfaceOptions
} from '../src/app/launch-surface'
import type { HostPort, LaunchCommandsReading, LaunchSurfaceReading } from '../src/host/port'

/** A port that lets the hook watch the connection and says nothing else. */
function port(): HostPort {
  return {
    onConnection: () => Promise.resolve(() => undefined)
  } as unknown as HostPort
}

/** Reads the test answers by hand: how many started, and the answer of the oldest. */
function held<T>(): {
  readonly read: () => Promise<T>
  readonly started: () => number
  readonly answer: (value: T) => Promise<void>
} {
  const waiting: ((value: T) => void)[] = []
  let started = 0
  return {
    read: () => {
      started += 1
      return new Promise<T>((resolve) => {
        waiting.push(resolve)
      })
    },
    started: () => started,
    answer: async (value) => {
      waiting.shift()?.(value)
      await act(async () => {
        await Promise.resolve()
        await Promise.resolve()
      })
    }
  }
}

const SURFACE: LaunchSurfaceReading = { state: 'not_served' }
const LISTED = (labels: readonly string[]): LaunchCommandsReading => ({
  state: 'served',
  list: {
    revision: String(labels.length),
    commands: labels.map((label) => ({ label, program: label.toLowerCase(), arguments: [] }))
  }
})

/** Runs the hook with the options the test changes between renders. */
function run(
  surface: () => Promise<LaunchSurfaceReading>,
  first: LaunchSurfaceOptions
): {
  readonly result: { readonly current: ReturnType<typeof useLaunchSurface> }
  readonly options: (next: LaunchSurfaceOptions) => void
} {
  const fake = port()
  const { result, rerender } = renderHook(
    ({ options }: { options: LaunchSurfaceOptions }) => useLaunchSurface(fake, surface, 0, options),
    { initialProps: { options: first } }
  )
  return {
    result,
    options: (next) => {
      rerender({ options: next })
    }
  }
}

/** The inputs of a view the test drives: the live count, and what the page has rendered. */
function typing(): {
  readonly options: (wake: number) => LaunchSurfaceOptions
  readonly type: () => void
  readonly settle: () => void
} {
  let counts: InputCounts = { submitted: 0, settled: 0 }
  return {
    options: (wake) => ({ wake, inputs: { now: () => counts, rendered: counts } }),
    type: () => {
      counts = { ...counts, submitted: counts.submitted + 1 }
    },
    settle: () => {
      counts = { ...counts, settled: counts.settled + 1 }
    }
  }
}

describe('what wakes the launch read', () => {
  beforeEach(() => {
    vi.useFakeTimers()
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it('a_state_the_view_publishes_wakes_the_launch_read', async () => {
    const surface = held<LaunchSurfaceReading>()
    const { options } = run(surface.read, { wake: 0 })
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0)
    })
    expect(surface.started()).toBe(1)
    await surface.answer(SURFACE)
    await act(async () => {
      await vi.advanceTimersByTimeAsync(300)
    })

    // Without the wake the read would wait out the cadence.
    options({ wake: 1 })
    expect(surface.started()).toBe(2)
    expect(LAUNCH_SURFACE_CADENCE_MS).toBeGreaterThan(300)
  })

  it('a_wake_round_reads_no_list', async () => {
    const surface = held<LaunchSurfaceReading>()
    const list = held<LaunchCommandsReading>()
    const { options } = run(surface.read, { wake: 0, readList: list.read })
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0)
    })
    await surface.answer(SURFACE)
    await list.answer(LISTED(['Claude']))
    expect([surface.started(), list.started()]).toEqual([1, 1])

    for (let wake = 1; wake <= 3; wake += 1) {
      await act(async () => {
        await vi.advanceTimersByTimeAsync(300)
      })
      options({ wake, readList: list.read })
      await surface.answer(SURFACE)
    }
    expect(surface.started()).toBe(4)
    expect(list.started()).toBe(1)
  })
})

describe('what darkens the buttons', () => {
  beforeEach(() => {
    vi.useFakeTimers()
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  /** A hook whose first read has answered with no input made. */
  async function lit(): Promise<{
    readonly result: ReturnType<typeof run>['result']
    readonly options: ReturnType<typeof run>['options']
    readonly surface: ReturnType<typeof held<LaunchSurfaceReading>>
    readonly keys: ReturnType<typeof typing>
  }> {
    const surface = held<LaunchSurfaceReading>()
    const keys = typing()
    const { result, options } = run(surface.read, keys.options(0))
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0)
    })
    await surface.answer(SURFACE)
    expect(result.current.dark).toBe(false)
    return { result, options, surface, keys }
  }

  it('a_key_the_page_sends_darkens_the_buttons_before_any_read_answers', async () => {
    const { result, options, keys } = await lit()
    keys.type()
    options(keys.options(0))
    expect(result.current.dark).toBe(true)
  })

  it('a_held_input_keeps_the_buttons_dark', async () => {
    const { result, options, surface, keys } = await lit()
    keys.type()
    options(keys.options(1))
    await act(async () => {
      await vi.advanceTimersByTimeAsync(300)
    })
    // The read the wake started began while the input was held, and says nothing of where it left
    // the prompt.
    await surface.answer(SURFACE)
    expect(result.current.dark).toBe(true)
  })

  it('a_second_input_queued_behind_a_held_one_keeps_them_dark_until_both_settle', async () => {
    const { result, options, surface, keys } = await lit()
    keys.type()
    keys.type()
    keys.settle()
    options(keys.options(1))
    await act(async () => {
      await vi.advanceTimersByTimeAsync(300)
    })
    await surface.answer(SURFACE)
    expect(result.current.dark).toBe(true)

    keys.settle()
    options(keys.options(2))
    // Settled, but the newest answer began before that: still dark until a read that started after.
    expect(result.current.dark).toBe(true)
    await act(async () => {
      await vi.advanceTimersByTimeAsync(300)
    })
    await surface.answer(SURFACE)
    expect(result.current.dark).toBe(false)
  })

  it('a_read_started_before_the_last_input_settled_does_not_light_them', async () => {
    const { result, options, surface, keys } = await lit()
    keys.type()
    options(keys.options(1))
    await act(async () => {
      await vi.advanceTimersByTimeAsync(300)
    })
    expect(surface.started()).toBe(2)
    // The input settles while that read is out; the read, which started before, answers after.
    keys.settle()
    options(keys.options(1))
    expect(result.current.dark).toBe(true)
    await surface.answer(SURFACE)
    expect(result.current.dark).toBe(true)
  })
})

describe('when the saved launch commands are read', () => {
  beforeEach(() => {
    vi.useFakeTimers()
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it('a_wake_every_250_ms_cannot_postpone_the_list_and_a_command_removed_elsewhere_is_seen_at_its_deadline', async () => {
    const surface = held<LaunchSurfaceReading>()
    const list = held<LaunchCommandsReading>()
    const { result, options } = run(surface.read, { wake: 0, readList: list.read })
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0)
    })
    await surface.answer(SURFACE)
    await list.answer(LISTED(['Claude', 'Codex']))
    expect(result.current.list).toEqual(LISTED(['Claude', 'Codex']))

    // The command is removed elsewhere. Output wakes the surface's read every 250 ms from now on,
    // each wake answered at once, and the surface's own cadence is pushed back by every one.
    for (let wake = 1; wake <= 7; wake += 1) {
      await act(async () => {
        await vi.advanceTimersByTimeAsync(250)
      })
      options({ wake, readList: list.read })
      await surface.answer(SURFACE)
    }
    expect(surface.started()).toBe(8)
    expect(list.started()).toBe(1)
    expect(result.current.list).toEqual(LISTED(['Claude', 'Codex']))

    // The list's deadline is its last read and a cadence, and the wakes did not move it.
    await act(async () => {
      await vi.advanceTimersByTimeAsync(250)
    })
    expect(list.started()).toBe(2)
    await list.answer(LISTED(['Claude']))
    expect(result.current.list).toEqual(LISTED(['Claude']))
  })

  it('a_list_read_in_flight_is_answered_after_a_wake_started_a_surface_read', async () => {
    const surface = held<LaunchSurfaceReading>()
    const list = held<LaunchCommandsReading>()
    const { result, options } = run(surface.read, { wake: 0, readList: list.read })
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0)
    })
    await surface.answer(SURFACE)

    // Output wakes the surface's read while the list read is still out; the list's answer is shown.
    for (let wake = 1; wake <= 3; wake += 1) {
      await act(async () => {
        await vi.advanceTimersByTimeAsync(300)
      })
      options({ wake, readList: list.read })
      await surface.answer(SURFACE)
    }
    expect(list.started()).toBe(1)
    await list.answer(LISTED(['Claude']))
    expect(result.current.list).toEqual(LISTED(['Claude']))
  })

  it('a_surface_read_in_flight_is_answered_after_the_list_read_began', async () => {
    const surface = held<LaunchSurfaceReading>()
    const list = held<LaunchCommandsReading>()
    const { result } = run(surface.read, { wake: 0, readList: list.read })
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0)
    })
    // The list read began after the surface read, which is still out.
    expect([surface.started(), list.started()]).toEqual([1, 1])
    await surface.answer(SURFACE)
    expect(result.current.reading).toEqual(SURFACE)
  })

  it('a_host_that_does_not_serve_the_list_is_asked_no_more_and_nothing_is_said', async () => {
    const surface = held<LaunchSurfaceReading>()
    const list = held<LaunchCommandsReading>()
    const { result } = run(surface.read, { wake: 0, readList: list.read })
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0)
    })
    await surface.answer(SURFACE)
    await list.answer({ state: 'not_served' })
    await act(async () => {
      await vi.advanceTimersByTimeAsync(10 * LAUNCH_SURFACE_CADENCE_MS)
    })
    expect(list.started()).toBe(1)
    expect(result.current.list).toBeNull()
    expect(result.current.listUnread).toBeNull()
  })

  it('a_list_that_cannot_be_read_keeps_the_last_one_and_says_why_beside_it', async () => {
    const surface = held<LaunchSurfaceReading>()
    let answers = 0
    const readList = vi.fn(() => {
      answers += 1
      return answers === 1
        ? Promise.resolve(LISTED(['Claude']))
        : Promise.reject(new Error('The saved launch commands could not be read.'))
    })
    const { result } = run(surface.read, { wake: 0, readList })
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0)
    })
    await surface.answer(SURFACE)
    expect(result.current.list).toEqual(LISTED(['Claude']))
    await act(async () => {
      await vi.advanceTimersByTimeAsync(LAUNCH_SURFACE_CADENCE_MS)
    })
    expect(result.current.list).toEqual(LISTED(['Claude']))
    expect(result.current.listUnread).toContain('could not be read')
  })
})
