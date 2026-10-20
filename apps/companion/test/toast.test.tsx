/**
 * A passing message goes by itself, in a time that grows with its words, and is drawn in the place
 * the newest open surface keeps for it.
 *
 * Its words may be too many for their box. They are read by scrolling the box, which the keyboard can
 * do, and the message still goes in its time: a timer that waited for the person to read to the end
 * of a long message would leave a message that is never dismissed on the screen.
 */

import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { Toast, type ToastMessage } from '../src/components/ui'
import {
  offerToastDock,
  toastDwell,
  TOAST_CEILING_MS,
  TOAST_FLOOR_MS,
  TOAST_FLOOR_WITH_ACTION_MS,
  TOAST_WORD_MS
} from '../src/components/toast'

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

describe('the time a message stays', () => {
  const words = (count: number): string => Array.from({ length: count }, () => 'word').join(' ')

  it('has a floor, longer where the message offers something to do', () => {
    expect(toastDwell('Saved.', false)).toBe(TOAST_FLOOR_MS)
    expect(toastDwell('Saved.', true)).toBe(TOAST_FLOOR_WITH_ACTION_MS)
  })

  it('grows with the words, and stops at a ceiling', () => {
    const long = Math.ceil(TOAST_FLOOR_WITH_ACTION_MS / TOAST_WORD_MS) + 10
    expect(toastDwell(words(long), false)).toBe(long * TOAST_WORD_MS)
    expect(toastDwell(words(long), true)).toBe(long * TOAST_WORD_MS)
    expect(toastDwell(words(10_000), false)).toBe(TOAST_CEILING_MS)
  })
})

describe('a passing message', () => {
  it('goes after its time when its words fit', () => {
    const dismissed = vi.fn()
    render(<Toast message={MESSAGE} onDismiss={dismissed} />)
    expect(screen.getByText(MESSAGE.text)).not.toHaveAttribute('tabindex')

    act(() => {
      vi.advanceTimersByTime(TOAST_FLOOR_MS - 1)
    })
    expect(dismissed).not.toHaveBeenCalled()
    act(() => {
      vi.advanceTimersByTime(1)
    })
    expect(dismissed).toHaveBeenCalledTimes(1)
  })

  it('goes in its time though its words overflow their box, and the box can be reached from the keyboard', () => {
    measuring(500, 100)
    const dismissed = vi.fn()
    const long = { ...MESSAGE, text: Array.from({ length: 200 }, () => 'word').join(' ') }
    render(<Toast message={long} onDismiss={dismissed} />)
    expect(screen.getByText(long.text)).toHaveAttribute('tabindex', '0')

    act(() => {
      vi.advanceTimersByTime(TOAST_CEILING_MS - 1)
    })
    expect(dismissed).not.toHaveBeenCalled()
    act(() => {
      vi.advanceTimersByTime(1)
    })
    expect(dismissed).toHaveBeenCalledTimes(1)
  })

  it('is held by focus in its words box, which is how a keyboard reads a long message', () => {
    measuring(500, 100)
    const dismissed = vi.fn()
    render(<Toast message={MESSAGE} onDismiss={dismissed} />)
    act(() => {
      screen.getByText(MESSAGE.text).focus()
    })
    act(() => {
      vi.advanceTimersByTime(TOAST_CEILING_MS * 2)
    })
    expect(dismissed).not.toHaveBeenCalled()
  })
})

describe('where a message is drawn', () => {
  /** A place a surface keeps for a message, in the document. */
  function dockInDocument(): HTMLElement {
    const dock = document.createElement('div')
    dock.setAttribute('data-testid', 'dock')
    document.body.append(dock)
    return dock
  }

  it('is in the place a surface offers while it is open, and back where it was when the surface goes', () => {
    render(<Toast message={MESSAGE} onDismiss={() => undefined} />)
    expect(screen.getByRole('status').parentElement).toBe(document.body.firstElementChild)

    const dock = dockInDocument()
    let take: () => void = () => undefined
    act(() => {
      take = offerToastDock(dock)
    })
    expect(within(dock).getByText(MESSAGE.text)).toBeTruthy()
    expect(within(dock).getByRole('button', { name: 'Dismiss' })).toBeTruthy()

    act(() => {
      take()
    })
    expect(within(dock).queryByText(MESSAGE.text)).toBeNull()
    expect(screen.getByText(MESSAGE.text)).toBeTruthy()
    dock.remove()
  })

  it('keeps its time across a move: neither the surface opening nor closing starts it again', () => {
    const dismissed = vi.fn()
    render(<Toast message={MESSAGE} onDismiss={dismissed} />)
    act(() => {
      vi.advanceTimersByTime(TOAST_FLOOR_MS - 1000)
    })
    const dock = dockInDocument()
    let take: () => void = () => undefined
    act(() => {
      take = offerToastDock(dock)
    })
    act(() => {
      vi.advanceTimersByTime(500)
    })
    act(() => {
      take()
    })
    expect(dismissed).not.toHaveBeenCalled()
    // 1000 ms from the end of the first stretch of its time, however it was moved about meanwhile.
    act(() => {
      vi.advanceTimersByTime(500)
    })
    expect(dismissed).toHaveBeenCalledTimes(1)
    dock.remove()
  })

  it('does not take the focus when it moves into a surface, and a pointer that was on it does not hold it there', () => {
    const dismissed = vi.fn()
    render(<Toast message={MESSAGE} onDismiss={dismissed} />)
    fireEvent.pointerEnter(screen.getByRole('status'))
    const before = document.activeElement
    const dock = dockInDocument()
    act(() => {
      offerToastDock(dock)
    })
    expect(document.activeElement).toBe(before)
    // The pointer was on the card the message was drawn in before; this one is another, and the pointer
    // is not on it until it enters it.
    act(() => {
      vi.advanceTimersByTime(TOAST_FLOOR_MS)
    })
    expect(dismissed).toHaveBeenCalledTimes(1)
    dock.remove()
  })
})
