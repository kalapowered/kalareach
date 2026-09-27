/**
 * Where the focus goes when control of the program ends under it.
 *
 * While a raw view controls the program the focus is often in its program keyboard or on one of the
 * phone's terminal keys. When control ends the keyboard goes and the keys are disabled, so the focus
 * would be left nowhere. It goes where the person can go on instead: to the mode button, which takes
 * control again, or, once the view has ended, to Attach again. The destination may not take the
 * focus at once: a disabled button takes none, and on a phone the bar holding the mode button is
 * hidden while a software keyboard is up, which the keyboard's own field going makes it leave. So the
 * move is owed until the destination can take it. Focus the person puts anywhere else first settles
 * it, and so does the destination leaving the page with its view.
 */

import { useLayoutEffect, useRef, type FocusEvent } from 'react'

/** Whether `element` can take the focus now: in the page, enabled, and shown. */
function takesFocus(element: HTMLElement): boolean {
  if (!element.isConnected || element.matches(':disabled')) return false
  return typeof element.checkVisibility === 'function' ? element.checkVisibility() : true
}

/**
 * Moves the focus that the end of control leaves nowhere to `destination()`, as soon as it can take
 * it. `heldFor` says whether the focus at an element is focus control held: in the program keyboard,
 * or on a terminal key. Returns the focus listener for the part of the page those are in, which
 * remembers where the focus last was.
 */
export function useFocusWhenControlEnds({
  controlling,
  heldFor,
  destination
}: {
  readonly controlling: boolean
  readonly heldFor: (element: Element | null) => boolean
  readonly destination: () => HTMLElement | null
}): (event: FocusEvent) => void {
  const last = useRef<Element | null>(null)
  const was = useRef(controlling)
  const owed = useRef(false)
  // After every commit, so a destination that becomes able to take the focus is found as it does.
  useLayoutEffect(() => {
    const active = document.activeElement
    const nowhere = active === null || active === document.body
    if (was.current && !controlling && (heldFor(active) || (nowhere && heldFor(last.current)))) {
      owed.current = true
    }
    was.current = controlling
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
