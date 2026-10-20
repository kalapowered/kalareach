/**
 * A passing message goes by itself, in a time that grows with its words, and is drawn in the place
 * the newest open surface keeps for it.
 *
 * Its words may be too many for their box. They are read by scrolling the box, which the keyboard can
 * do, and the message still goes in its time: a timer that waited for the person to read to the end
 * of a long message would leave a message that is never dismissed on the screen.
 */

import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react'
import type { ReactNode } from 'react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { AnnouncementScope, Announcer } from '../src/components/announcements'
import { Sheet, Toast, type ToastMessage } from '../src/components/ui'
import {
  offerToastDock,
  toastDwell,
  TOAST_CEILING_MS,
  TOAST_FLOOR_MS,
  TOAST_FLOOR_WITH_ACTION_MS,
  TOAST_LETTERS_PER_WORD,
  TOAST_WORD_MS
} from '../src/components/toast'
import { addedTo, heardIn, regionsOf, watched } from './live-regions'

const MESSAGE: ToastMessage = { id: 1, text: 'A message that is read in passing.', tone: 'success' }

/** The card a message is drawn in. */
function cardOf(message: ToastMessage): HTMLElement {
  const card = screen.getByText(message.text).closest<HTMLElement>('.toast')
  if (card === null) throw new Error('the message is not in a card')
  return card
}

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
      take = offerToastDock(dock, new Announcer())
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
      take = offerToastDock(dock, new Announcer())
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
    fireEvent.pointerEnter(cardOf(MESSAGE))
    const before = document.activeElement
    const dock = dockInDocument()
    let take: () => void = () => undefined
    act(() => {
      take = offerToastDock(dock, new Announcer())
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
    fireEvent.pointerEnter(cardOf(MESSAGE))
    const dock = dockInDocument()
    let take: () => void = () => undefined
    act(() => {
      take = offerToastDock(dock, new Announcer())
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
      take = offerToastDock(dock, new Announcer())
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

  it('brings the focus to the control that closes the dialog when the message that had it goes in it', () => {
    const dialog = document.createElement('div')
    dialog.setAttribute('role', 'dialog')
    const decision = document.createElement('button')
    const dock = document.createElement('div')
    const close = document.createElement('button')
    close.setAttribute('data-sheet-close', '')
    dialog.append(decision, dock, close)
    document.body.append(dialog)

    render(<Toast message={MESSAGE} onDismiss={() => undefined} />)
    let take: () => void = () => undefined
    act(() => {
      take = offerToastDock(dock, new Announcer())
    })
    const dismiss = within(dock).getByRole('button', { name: 'Dismiss' })
    // It came to the message from nowhere (a press that had focus on nothing), and has it now.
    dismiss.focus()
    act(() => {
      dismiss.click()
    })
    expect(document.activeElement, 'the control that closes the dialog has it, not the decision').toBe(close)
    act(() => {
      take()
    })
    dialog.remove()
  })

  it('goes on to the control that closes the dialog when where the focus came from refuses it', () => {
    const dialog = document.createElement('div')
    dialog.setAttribute('role', 'dialog')
    const origin = document.createElement('button')
    const dock = document.createElement('div')
    const close = document.createElement('button')
    close.setAttribute('data-sheet-close', '')
    dialog.append(origin, dock, close)
    document.body.append(dialog)

    render(<Toast message={MESSAGE} onDismiss={() => undefined} />)
    let take: () => void = () => undefined
    act(() => {
      take = offerToastDock(dock, new Announcer())
    })
    const dismiss = within(dock).getByRole('button', { name: 'Dismiss' })
    origin.focus()
    fireEvent.focusIn(dismiss, { relatedTarget: origin })
    dismiss.focus()
    // The control the focus came from is not usable by the time the message goes.
    origin.disabled = true
    act(() => {
      dismiss.click()
    })
    expect(document.activeElement, 'the focus is not left on nothing').toBe(close)
    act(() => {
      take()
    })
    dialog.remove()
  })

  it('forgets where the focus came from when it comes in again from nowhere', () => {
    const dialog = document.createElement('div')
    dialog.setAttribute('role', 'dialog')
    const origin = document.createElement('button')
    const dock = document.createElement('div')
    const close = document.createElement('button')
    close.setAttribute('data-sheet-close', '')
    dialog.append(origin, dock, close)
    document.body.append(dialog)

    render(<Toast message={MESSAGE} onDismiss={() => undefined} />)
    let take: () => void = () => undefined
    act(() => {
      take = offerToastDock(dock, new Announcer())
    })
    const dismiss = within(dock).getByRole('button', { name: 'Dismiss' })
    origin.focus()
    fireEvent.focusIn(dismiss, { relatedTarget: origin })
    dismiss.focus()
    dismiss.blur()
    // It comes in again with no control to name, as a press does where the focus was on nothing.
    fireEvent.focusIn(dismiss, { relatedTarget: null })
    dismiss.focus()
    act(() => {
      dismiss.click()
    })
    expect(document.activeElement, 'the old origin is not given the focus').toBe(close)
    act(() => {
      take()
    })
    dialog.remove()
  })
})

describe('a passing message is said to a screen reader', () => {
  /**
   * The application's scope with a message in it, and a sheet that has the scope of a dialog: open,
   * closed and still leaving, or not drawn at all (`null`).
   */
  function Page({
    message,
    sheet = false
  }: {
    readonly message: ToastMessage | null
    readonly sheet?: boolean | null
  }): ReactNode {
    return (
      <AnnouncementScope>
        <Toast message={message} onDismiss={() => undefined} />
        {sheet === null ? null : (
          <Sheet open={sheet} title="A sheet" closeLabel="Close the sheet" onClose={() => undefined}>
            <p>The sheet’s body.</p>
          </Sheet>
        )}
      </AnnouncementScope>
    )
  }

  /** Mounts the page and returns what a test reads: the holder, and the two regions as they are. */
  function mount(message: ToastMessage | null, sheet: boolean | null = false) {
    const holder = document.createElement('div')
    document.body.append(holder)
    const view = render(<Page message={message} sheet={sheet} />, { container: holder })
    const regions = () => {
      const dialog = holder.querySelector('[data-testid="sheet"]')
      const all = regionsOf(holder)
      return {
        page: all.find((region) => !(dialog?.contains(region) ?? false)),
        sheet: all.find((region) => dialog?.contains(region) ?? false)
      }
    }
    return { holder, regions, show: (next: ToastMessage | null, open: boolean | null = sheet) => {
      view.rerender(<Page message={next} sheet={open} />)
    } }
  }

  /** How many times `words` are in a region of the page, in the page's and the sheet's together. */
  function timesHeard(regions: ReturnType<ReturnType<typeof mount>['regions']>, words: string): number {
    return [regions.page, regions.sheet].flatMap((region) => (region ? heardIn(region) : [])).filter((each) => each === words).length
  }

  it('puts its words into a region that was in the page before them, and is no live region itself', () => {
    const { holder, regions, show } = mount(null)
    const region = regions().page
    expect(region).toBeDefined()
    if (region === undefined) return
    expect(heardIn(region)).toEqual([])

    const watching = watched(holder)
    show(MESSAGE)
    const records = watching.records()
    watching.stop()
    expect(heardIn(region)).toEqual([MESSAGE.text])
    expect(regions().page, 'the region is the one that was there').toBe(region)
    expect(
      records.some((record) => Array.from(record.addedNodes).some((node) => node.contains(region))),
      'the region was not added with the words'
    ).toBe(false)
    const card = holder.querySelector('.toast')
    expect(card?.matches('[aria-live], [role="status"]'), 'the card is not a region').toBe(false)
    expect(card?.querySelector('[aria-live], [role="status"]'), 'nor holds one').toBeNull()
  })

  it('is not said again when it moves into a sheet that opens over it, nor when the sheet goes', () => {
    const { holder, regions, show } = mount(MESSAGE)
    expect(timesHeard(regions(), MESSAGE.text)).toBe(1)

    const before = watched(holder)
    show(MESSAGE, true)
    expect(holder.querySelector('[data-testid="sheet"] .toast'), 'the card is in the sheet').not.toBeNull()
    const inSheet = regions()
    expect(timesHeard(inSheet, MESSAGE.text), 'said once, wherever it is').toBe(1)
    expect(inSheet.sheet).toBeDefined()
    expect(addedTo(inSheet.sheet as HTMLElement, before.records()), 'nothing was added to the sheet’s region').toEqual([])
    before.stop()

    // The sheet starts to leave: the card goes back to the page, and its words stay where they are.
    const leaving = watched(holder)
    show(MESSAGE, false)
    expect(holder.querySelector('[data-testid="sheet"] .toast'), 'the card has left the sheet').toBeNull()
    const after = regions()
    expect(timesHeard(after, MESSAGE.text)).toBe(1)
    expect(leaving.records().filter((record) => record.addedNodes.length > 0 && (record.target as HTMLElement).closest('[data-announcements]') !== null)).toEqual([])
    leaving.stop()
  })

  it('says new words in the region of the sheet it is in, and takes the old ones away', () => {
    const { holder, regions, show } = mount(MESSAGE)
    show(MESSAGE, true)
    const words = 'Different words.'
    const watching = watched(holder)
    show({ ...MESSAGE, text: words }, true)
    const now = regions()
    expect(now.sheet && heardIn(now.sheet)).toEqual([words])
    expect(now.page && heardIn(now.page), 'not the page’s').toEqual([])
    expect(timesHeard(now, MESSAGE.text)).toBe(0)
    expect(addedTo(now.sheet as HTMLElement, watching.records())).toEqual([words])
    watching.stop()
  })

  it('says the same words again when it is told they are said anew', () => {
    const { holder, regions, show } = mount({ ...MESSAGE, said: 0 })
    const watching = watched(holder)
    show({ ...MESSAGE, said: 1 })
    const now = regions()
    expect(now.page && heardIn(now.page)).toEqual([MESSAGE.text])
    expect(addedTo(now.page as HTMLElement, watching.records()), 'a new paragraph is a new announcement').toEqual([MESSAGE.text])
    watching.stop()
  })

  it('is said in the region of the sheet that is open when it arrives, and only there', () => {
    const { regions, show } = mount(null, true)
    show(MESSAGE, true)
    const now = regions()
    expect(now.sheet && heardIn(now.sheet)).toEqual([MESSAGE.text])
    expect(now.page && heardIn(now.page)).toEqual([])
  })

  it('is said in the region of the sheet that opens in the update it arrives in', () => {
    const { regions, show } = mount(null, false)
    show(MESSAGE, true)
    const now = regions()
    expect(now.sheet && heardIn(now.sheet)).toEqual([MESSAGE.text])
    expect(now.page && heardIn(now.page), 'not behind the dialog').toEqual([])
  })

  it('is said on the page when it arrives in the update that closes the sheet, which is still on its way out', () => {
    const { holder, regions, show } = mount(null, true)
    show(MESSAGE, false)
    expect(holder.querySelector('[data-testid="sheet"]'), 'the sheet is still leaving').not.toBeNull()
    const now = regions()
    expect(now.page && heardIn(now.page)).toEqual([MESSAGE.text])
    expect(now.sheet && heardIn(now.sheet), 'not in the region that goes with the sheet').toEqual([])
  })

  it('is said on the page when it arrives in the update that takes the sheet away', () => {
    const { holder, regions, show } = mount(null, true)
    show(MESSAGE, null)
    expect(holder.querySelector('[data-testid="sheet"]')).toBeNull()
    expect(regions().page && heardIn(regions().page as HTMLElement)).toEqual([MESSAGE.text])
  })

  it('leaves the region when it goes', () => {
    const { regions, show } = mount(null, true)
    show(MESSAGE, true)
    expect(timesHeard(regions(), MESSAGE.text)).toBe(1)
    show(null, true)
    expect(timesHeard(regions(), MESSAGE.text)).toBe(0)
  })
})
