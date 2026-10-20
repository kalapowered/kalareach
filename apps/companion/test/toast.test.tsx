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
  TOAST_LETTERS_PER_WORD,
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

  it('counts a name with no break in it for the letters it has', () => {
    const name = 'a'.repeat(TOAST_LETTERS_PER_WORD * 40)
    expect(toastDwell(name, false)).toBe(40 * TOAST_WORD_MS)
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
    const dock = dockInDocument()
    expect(within(dock).queryByText(MESSAGE.text)).toBeNull()
    expect(screen.getByText(MESSAGE.text)).toBeTruthy()

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
    let take: () => void = () => undefined
    act(() => {
      take = offerToastDock(dock)
    })
    expect(document.activeElement).toBe(before)
    // The pointer was on the card the message was drawn in before; this one is another, and the pointer
    // is not on it until it enters it.
    act(() => {
      vi.advanceTimersByTime(TOAST_FLOOR_MS)
    })
    expect(dismissed).toHaveBeenCalledTimes(1)
    act(() => {
      take()
    })
    dock.remove()
  })

  it('does not hold the place a message returns to by what was on it before it left', () => {
    const dismissed = vi.fn()
    render(<Toast message={MESSAGE} onDismiss={dismissed} />)
    // The pointer rests on the message where it was first drawn, and a surface opens over it and
    // goes again without the pointer crossing the card in it.
    fireEvent.pointerEnter(screen.getByRole('status'))
    const dock = dockInDocument()
    let take: () => void = () => undefined
    act(() => {
      take = offerToastDock(dock)
    })
    act(() => {
      take()
    })
    act(() => {
      vi.advanceTimersByTime(TOAST_FLOOR_MS)
    })
    expect(dismissed).toHaveBeenCalledTimes(1)
    dock.remove()
  })

  it('goes at the time it had when the application gives it a new way to dismiss it', () => {
    const first = vi.fn()
    const second = vi.fn()
    const { rerender } = render(<Toast message={MESSAGE} onDismiss={first} />)
    act(() => {
      vi.advanceTimersByTime(TOAST_FLOOR_MS - 1000)
    })
    rerender(<Toast message={MESSAGE} onDismiss={second} />)
    act(() => {
      vi.advanceTimersByTime(999)
    })
    expect(first).not.toHaveBeenCalled()
    expect(second).not.toHaveBeenCalled()
    act(() => {
      vi.advanceTimersByTime(1)
    })
    expect(first).not.toHaveBeenCalled()
    expect(second).toHaveBeenCalledTimes(1)
  })

  it('gives the focus back to where it came from when it is dismissed, and leaves it where an action puts it', () => {
    const before = document.createElement('button')
    document.body.append(before)
    const acted = vi.fn()
    const dismissed = vi.fn()
    render(
      <Toast
        message={{ ...MESSAGE, action: { label: 'Review', act: acted } }}
        onDismiss={dismissed}
      />
    )
    before.focus()
    const dismiss = screen.getByRole('button', { name: 'Dismiss' })
    fireEvent.focusIn(dismiss, { relatedTarget: before })
    dismiss.focus()
    expect(document.activeElement).toBe(dismiss)
    act(() => {
      dismiss.click()
    })
    expect(dismissed).toHaveBeenCalledTimes(1)
    expect(document.activeElement).toBe(before)

    // An action decides where the focus goes by itself: the message does not take it from it.
    const review = screen.getByRole('button', { name: 'Review' })
    fireEvent.focusIn(review, { relatedTarget: before })
    review.focus()
    act(() => {
      review.click()
    })
    expect(acted).toHaveBeenCalledTimes(1)
    expect(document.activeElement).not.toBe(before)
    before.remove()
  })

  it('moves no focus when it is pressed without taking the focus, and none out of the dialog it is in', () => {
    // A press in WebKit does not focus a button. The control the person tabbed in from, on the page
    // behind, is not given the focus when the message that moved into a dialog is pressed.
    const behind = document.createElement('button')
    document.body.append(behind)
    const dialog = document.createElement('div')
    dialog.setAttribute('role', 'dialog')
    const inside = document.createElement('button')
    const dock = document.createElement('div')
    dialog.append(inside, dock)
    document.body.append(dialog)

    const dismissed = vi.fn()
    render(<Toast message={MESSAGE} onDismiss={dismissed} />)
    behind.focus()
    const dismissOnPage = screen.getByRole('button', { name: 'Dismiss' })
    fireEvent.focusIn(dismissOnPage, { relatedTarget: behind })
    // The dialog opens over it and the message moves into it.
    let take: () => void = () => undefined
    act(() => {
      take = offerToastDock(dock)
    })
    inside.focus()
    const dismissInDialog = within(dock).getByRole('button', { name: 'Dismiss' })
    act(() => {
      dismissInDialog.click()
    })
    expect(dismissed).toHaveBeenCalledTimes(1)
    expect(document.activeElement, 'the page behind is not given the focus').not.toBe(behind)
    expect(document.activeElement, 'and the focus that was in the dialog is left where it was').toBe(inside)
    act(() => {
      take()
    })
    behind.remove()
    dialog.remove()
  })

  it('brings the focus to the dialog\'s first stop, which commits nothing, when the message that had it goes in a dialog', () => {
    const dialog = document.createElement('div')
    dialog.setAttribute('role', 'dialog')
    const close = document.createElement('button')
    const dock = document.createElement('div')
    const decision = document.createElement('button')
    dialog.append(close, dock, decision)
    document.body.append(dialog)

    render(<Toast message={MESSAGE} onDismiss={() => undefined} />)
    let take: () => void = () => undefined
    act(() => {
      take = offerToastDock(dock)
    })
    const dismiss = within(dock).getByRole('button', { name: 'Dismiss' })
    // It came to the message from nowhere (a press that had focus on nothing), and has it now.
    dismiss.focus()
    act(() => {
      dismiss.click()
    })
    expect(document.activeElement, 'the control that closes the dialog has it, not a decision').toBe(close)
    act(() => {
      take()
    })
    dialog.remove()
  })
})
