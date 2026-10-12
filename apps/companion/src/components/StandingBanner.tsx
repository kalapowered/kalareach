/**
 * What a session screen says when its opening is over.
 *
 * An opening ends because the share it ran under ended, because the host will not open or keep the
 * session, or because the session closed. The screen keeps what it read and sends nothing more, and
 * this says why in the host's words, with the way out: back to the list, and, for a refusal, to try
 * the host again.
 *
 * The banner arrives with a change of opacity over 150 ms. A request for less motion, and a
 * keyboard press, have it arrive at once; the stylesheet decides both. The change is announced once,
 * through a status region that is always there, so a screen reader hears it however the banner
 * arrives. Focus stays where it is, unless the control it is on has just been turned off: then it
 * moves to the banner, so a keyboard or screen-reader user is not left on nothing.
 */

import { useEffect, useLayoutEffect, useRef, useState, type ReactNode, type RefObject } from 'react'

import { Button } from './ui'
import { announcementFor, wordsFor, type OpeningRecord } from '../model/openings'

/** Whether an element is a control that no longer takes the person's input. */
function turnedOff(element: Element | null): boolean {
  return (
    element instanceof HTMLElement &&
    (element.matches(':disabled') || element.getAttribute('aria-disabled') === 'true')
  )
}

/**
 * The banner for `record`, or only the status region when the opening is not over.
 *
 * `screen` is the element holding the controls the banner turns off, so the banner can tell that
 * the focus was on one of them.
 */
export function StandingBanner({
  record,
  screen,
  target,
  settled,
  onBack,
  onRetry
}: {
  readonly record: OpeningRecord | undefined
  readonly screen: RefObject<HTMLElement | null>
  /**
   * Something that changes when the controls the opening's end turns off have been turned off, which
   * can be a commit after the standing changed: the focus is looked at again then.
   */
  readonly settled?: string
  /** The least a finger can be asked to hit, in CSS pixels, for the surface. */
  readonly target: number
  readonly onBack: () => void
  readonly onRetry: () => void
}): ReactNode {
  const words = record === undefined ? null : wordsFor(record)
  const over = words !== null
  const banner = useRef<HTMLDivElement | null>(null)
  const [shown, setShown] = useState(false)
  // What the person had focused inside the screen, kept as it changes, because a browser may drop
  // the focus from a control that was turned off before this effect looks at it.
  const lastFocus = useRef<Element | null>(null)

  useEffect(() => {
    const root = screen.current
    if (root === null) return
    const held = (event: FocusEvent) => {
      lastFocus.current = event.target instanceof Element ? event.target : null
    }
    const dropped = (event: FocusEvent) => {
      // Focus that the person moved, or let go of, is theirs. Only a control that was turned off
      // under the focus keeps it here, because a browser may drop the focus from that.
      if (!turnedOff(event.target instanceof Element ? event.target : null)) lastFocus.current = null
    }
    root.addEventListener('focusin', held)
    root.addEventListener('focusout', dropped)
    return () => {
      root.removeEventListener('focusin', held)
      root.removeEventListener('focusout', dropped)
    }
  }, [screen])

  useLayoutEffect(() => {
    const element = banner.current
    if (!over || element === null) {
      setShown(false)
      return
    }
    // Style is flushed with the banner at zero opacity, so the change to one is a transition.
    void element.getBoundingClientRect()
    setShown(true)
    const active = document.activeElement
    const root = screen.current
    // The banner already has the focus, or the person has gone into it.
    if (active !== null && element.contains(active)) return
    const was = active === null || active === document.body ? lastFocus.current : active
    if (root !== null && was !== null && root.contains(was) && turnedOff(was)) {
      element.focus({ preventScroll: false })
    }
  }, [over, record?.standing?.state, screen, settled])

  return (
    <>
      <p className="visually-hidden" role="status" aria-live="polite" data-testid="standing-status">
        {announcementFor(record)}
      </p>
      {words === null ? null : (
        <div
          ref={banner}
          className={`banner ${words.tone} standing-banner`}
          data-shown={shown}
          data-testid="standing-banner"
          role="region"
          aria-label={words.title}
          tabIndex={-1}
        >
          <div className="spacer">
            <strong>{words.title}</strong>
            {words.detail}
          </div>
          <Button style={{ minBlockSize: target }} onClick={onBack}>
            Back
          </Button>
          {words.retry ? (
            <Button style={{ minBlockSize: target }} onClick={onRetry}>
              Try again
            </Button>
          ) : null}
        </div>
      )}
    </>
  )
}
