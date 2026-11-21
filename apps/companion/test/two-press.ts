/**
 * The clock of a case that presses a two-press control twice. A press that begins less than
 * `SECOND_PRESS_AFTER_MS` after the release that armed the control is not its second press, so a case
 * holds the clock still (only `performance`, the clock the control reads, so timers and the testing
 * library run as they do) and moves it past that time by hand before the second press.
 */

import { vi } from 'vitest'

import { SECOND_PRESS_AFTER_MS } from '../src/components/ui'

/** Holds the control's clock still at its present value; undo it with `vi.useRealTimers()`. */
export function holdTheClock(): void {
  vi.useFakeTimers({ toFake: ['performance'] })
}

/** Moves the held clock past the guard of a two-press control, as a person who pressed it twice on purpose does. */
export function afterTheGuard(): void {
  vi.advanceTimersByTime(SECOND_PRESS_AFTER_MS + 100)
}
