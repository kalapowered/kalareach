/**
 * Where the focus goes when the view's controls stop holding it.
 *
 * While a raw view controls the program the focus is often in its program keyboard, on one of the
 * phone's terminal keys, or on the mode button. When control ends the keyboard goes and the keys
 * are disabled, and when the view ends the mode button is disabled too, so the focus would be left
 * nowhere, or on a control that can no longer be used. It goes where the person can go on instead:
 * to the mode button, which takes control again, or, once the view has ended, to Attach again.
 *
 * Only a change of the view's state owes the move, and only when the change finds the focus on one
 * of the view's controls that can no longer take it, or nowhere after it was last on one of them. A
 * press on the terminal that selects its text owes nothing by itself, and focus the person has put
 * on any other control on the page stays theirs. The destination may not take the focus at once: a
 * disabled button takes none, and on a phone the bar holding the mode button is hidden while a
 * software keyboard is up, which the keyboard's own field going makes it leave. So the move is owed
 * until the destination can take it. Focus the person puts on any other control first settles it,
 * and so does the destination leaving the page with its view.
 *
 * Attach again is one of the view's controls unless the person pressed it with a pointer: opening
 * the view again removes the button with the view that ended, and the focus it held goes with it.
 */

import { useLayoutEffect, useRef } from 'react'

/** Whether `element` can take the focus now: in the page, enabled, and shown. */
function takesFocus(element: Element): boolean {
  if (!element.isConnected || element.matches(':disabled')) return false
  const control = element as HTMLElement
  return typeof control.checkVisibility === 'function' ? control.checkVisibility() : true
}

/**
 * Counts the control `id` among the view's own, unless the person's last press of it came from a
 * pointer. `showing` is whether the control is there: a control that shows again has not been
 * pressed yet.
 *
 * Opening the view again removes the control that asks for it, and the focus it held goes with it.
 * A view that opens again by itself does the same. Whoever had the focus there has nowhere to go on
 * from, so the focus is owed as it is for the view's other controls. A person with a pointer put
 * the focus where they pressed, and nothing of it is owed: a pointer's click counts its presses,
 * one or more, and a click that nothing pointed at, as from Enter or Space, counts none.
 */
export function useOwnControl(
  id: string,
  showing: boolean
): {
  /** Notes how the control was pressed: call it from the control's click handler. */
  readonly press: (event: { readonly detail: number }) => void
  /** Whether `element` is that control, and its last press was not a pointer's. */
  readonly held: (element: Element | null) => boolean
} {
  const pointer = useRef(false)
  useLayoutEffect(() => {
    if (showing) pointer.current = false
  }, [showing])
  return {
    press: (event) => {
      pointer.current = event.detail > 0
    },
    held: (element) => !pointer.current && element?.id === id
  }
}

/**
 * Moves the focus that a change of the view's `state` takes from the view's controls to
 * `destination()`, as soon as it can take it. `heldFor` says whether an element is one of those
 * controls: the program keyboard, a terminal key, the mode button.
 */
export function useFocusWhenControlEnds({
  state,
  heldFor,
  destination
}: {
  /** The view's state as far as its controls go: which of them there are, and which are usable. */
  readonly state: string
  readonly heldFor: (element: Element | null) => boolean
  readonly destination: () => HTMLElement | null
}): void {
  // Where on the page the focus last was, which says whose it was once it is nowhere.
  const last = useRef<Element | null>(null)
  const previous = useRef(state)
  const owed = useRef(false)
  const holds = useRef(heldFor)
  useLayoutEffect(() => {
    holds.current = heldFor
  })

  // Every focus on the page is remembered, and focus put on any other control settles the move,
  // whenever it happens.
  useLayoutEffect(() => {
    const focused = (event: FocusEvent) => {
      const target = event.target instanceof Element ? event.target : null
      last.current = target
      if (owed.current && !holds.current(target)) owed.current = false
    }
    document.addEventListener('focusin', focused, true)
    return () => {
      document.removeEventListener('focusin', focused, true)
    }
  }, [])

  // After every commit, so a destination that becomes able to take the focus is found as it does.
  useLayoutEffect(() => {
    const active = document.activeElement
    const nowhere = active === null || active === document.body
    if (previous.current !== state) {
      previous.current = state
      const lost = nowhere ? heldFor(last.current) : heldFor(active) && !takesFocus(active)
      // Where the focus last was is used once: a later change finds it long gone, not lost to it.
      if (nowhere) last.current = null
      if (lost) owed.current = true
    }
    if (!owed.current) return
    if (!nowhere && !heldFor(active)) {
      owed.current = false
      return
    }
    const target = destination()
    // A destination that is not in the page is a view that has gone, as when the phone shows the
    // conversation instead: nothing is owed to one that comes later.
    if (target === null) {
      owed.current = false
      return
    }
    if (takesFocus(target)) {
      target.focus()
      owed.current = false
    }
  })
}
