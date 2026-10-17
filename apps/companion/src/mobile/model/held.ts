/**
 * What the phone is offered and holds, for the screens that draw it.
 *
 * The inbox draws the invitations and the sessions list draws the shares, from one read of one
 * book, so the two halves never disagree about the host and a half that is not shown asks for
 * nothing. A screen that draws either one is attached to the book while it is shown.
 */

import { useEffect, useSyncExternalStore } from 'react'

import { useHeldConnection } from '../../app/rights'
import { useApp } from '../../app/state'
import { bookOf, hostKeyOf, type HeldBook, type HeldView } from '../../model/held-shares'

/** The book of the port the page talks to. */
export function useHeldBook(): HeldBook {
  return bookOf(useApp().port)
}

/** What is held now, read for as long as the screen that calls this is shown. */
export function useHeld(): HeldView {
  const book = useHeldBook()
  const { paired, environmentId } = useHeldConnection()
  const key = hostKeyOf(paired, environmentId ?? null)
  useEffect(() => book.attach(), [book])
  useEffect(() => {
    book.connect(key)
  }, [book, key])
  return useSyncExternalStore(book.subscribe, book.snapshot)
}
