/**
 * What the phone is offered and holds, for the screens that draw it.
 *
 * The inbox draws the invitations and the sessions list draws the shares, from one read of one
 * book, so the two halves never disagree about the host and a half that is not shown asks for
 * nothing. A screen that draws either one is attached to the book while it is shown. Which host is
 * reached, and whether contact with it is up, is the shell's to say (`useReachedHost`), since it
 * is a fact about the device and not about the screen that happens to be shown.
 */

import { useEffect, useSyncExternalStore } from 'react'

import { useApp } from '../../app/state'
import {
  bookOf,
  waitingOffers,
  type HeldBook,
  type HeldView,
  type Reach
} from '../../model/held-shares'

/** The book of the port the page talks to. */
export function useHeldBook(): HeldBook {
  return bookOf(useApp().port)
}

/** What is held now, read for as long as the screen that calls this is shown. */
export function useHeld(): HeldView {
  const book = useHeldBook()
  useEffect(() => book.attach(), [book])
  return useSyncExternalStore(book.subscribe, book.snapshot)
}

/**
 * How many invitations wait for the phone's answer, for as long as the caller is shown. It reads
 * nothing itself: it follows what the screens that draw the book have learned.
 */
export function useWaitingInvitations(): number {
  const book = useHeldBook()
  return useSyncExternalStore(book.subscribe, () => waitingOffers(book.snapshot()).length)
}

/** Tells the book where the connection stands, each time the shell hears of a change. */
export function useReachedHost(reach: Reach | null): void {
  const book = useHeldBook()
  const connected = reach?.connected
  const paired = reach?.paired
  const environmentId = reach?.environmentId
  useEffect(() => {
    if (connected === undefined || paired === undefined || environmentId === undefined) return
    book.reach({ connected, paired, environmentId })
  }, [book, connected, paired, environmentId])
}
