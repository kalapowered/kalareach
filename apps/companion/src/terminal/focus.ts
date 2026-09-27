/**
 * Where the focus goes when the view's controls stop holding it.
 *
 * While a raw view controls the program the focus is often in its program keyboard, on one of the
 * phone's terminal keys, or on the mode button. When control ends the keyboard goes and the keys
 * are disabled, and when the view ends the mode button is disabled too, so the focus would be left
 * nowhere, or on a control that can no longer be used. It goes where the person can go on instead:
 * to the mode button, which takes control again, or, once the view has ended, to Attach again.
 *
 * Only a change of the view's state owes the move: focus the person takes away themselves, as with a
 * press on the terminal that selects its text, is theirs. The destination may not take the focus at
 * once: a disabled button takes none, and on a phone the bar holding the mode button is hidden while
 * a software keyboard is up, which the keyboard's own field going makes it leave. So the move is owed
 * until the destination can take it. Focus the person puts on any other control first settles it,
 * and so does the destination leaving the page with its view.
 */

import { useEffect, useLayoutEffect, useRef, type FocusEvent } from 'react'

/** Whether `element` can take the focus now: in the page, enabled, and shown. */
function takesFocus(element: Element): boolean {
  if (!element.isConnected || element.matches(':disabled')) return false
  const control = element as HTMLElement
  return typeof control.checkVisibility === 'function' ? control.checkVisibility() : true
}

/**
 * Moves the focus that a change of the view's `state` takes from the view's controls to
 * `destination()`, as soon as it can take it. `heldFor` says whether an element is one of those
 * controls: the program keyboard, a terminal key, the mode button. Returns the focus listener for
 * the part of the page they are in, which remembers where the focus last was.
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
}): (event: FocusEvent) => void {
  const last = useRef<Element | null>(null)
  const previous = useRef(state)
  const owed = useRef(false)
  const holds = useRef(heldFor)
  useLayoutEffect(() => {
    holds.current = heldFor
  })

  // Focus the person puts on any other control settles the move, whenever it happens.
  useEffect(() => {
    const settle = (event: Event) => {
      if (owed.current && !holds.current(event.target as Element | null)) owed.current = false
    }
    document.addEventListener('focusin', settle, true)
    return () => {
      document.removeEventListener('focusin', settle, true)
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
  return (event) => {
    last.current = event.target
  }
}
