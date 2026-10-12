/**
 * A passing message goes by itself, unless its words are too many for their box.
 *
 * Words that overflow are read by scrolling, which a timer cannot wait for: the message stays until
 * the person dismisses it, and its words can be scrolled from the keyboard. A short message goes
 * after its time.
 */

import { act, cleanup, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { Toast, type ToastMessage } from '../src/components/ui'

const MESSAGE: ToastMessage = { id: 1, text: 'A message that is read in passing.', tone: 'success' }

/** Makes every box report `scrollHeight` of content in a box `clientHeight` tall. */
function measuring(scrollHeight: number, clientHeight: number): void {
  Object.defineProperty(HTMLElement.prototype, 'scrollHeight', { configurable: true, get: () => scrollHeight })
  Object.defineProperty(HTMLElement.prototype, 'clientHeight', { configurable: true, get: () => clientHeight })
}

beforeEach(() => {
  vi.useFakeTimers()
})

afterEach(() => {
  cleanup()
  vi.useRealTimers()
  Reflect.deleteProperty(HTMLElement.prototype, 'scrollHeight')
  Reflect.deleteProperty(HTMLElement.prototype, 'clientHeight')
})

describe('a passing message', () => {
  it('goes after its time when its words fit', () => {
    const dismissed = vi.fn()
    render(<Toast message={MESSAGE} onDismiss={dismissed} />)
    expect(screen.getByText(MESSAGE.text)).not.toHaveAttribute('tabindex')

    act(() => {
      vi.advanceTimersByTime(10_000)
    })
    expect(dismissed).toHaveBeenCalledTimes(1)
  })

  it('stays until it is dismissed when its words overflow their box, and the box can be reached from the keyboard', () => {
    measuring(500, 100)
    const dismissed = vi.fn()
    render(<Toast message={MESSAGE} onDismiss={dismissed} />)
    expect(screen.getByText(MESSAGE.text)).toHaveAttribute('tabindex', '0')

    act(() => {
      vi.advanceTimersByTime(60_000)
    })
    expect(dismissed).not.toHaveBeenCalled()
    // It is still there to be dismissed.
    screen.getByRole('button', { name: 'Dismiss' }).click()
    expect(dismissed).toHaveBeenCalledTimes(1)
  })
})
