/**
 * Keeping what a person is reading where it is while the list above it changes.
 *
 * A list that is read again every few seconds can gain a row above the one a person has scrolled to.
 * Chromium moves the scroll position by itself to keep the row in place (scroll anchoring); WebKit
 * does not, and the row under the person's finger jumps. Neither is left to the engine: the first
 * rows that are in view are remembered with where they are drawn in the scrolling area and where the
 * list was scrolled to, and when the list changes with the scroll position where it was, the scroll
 * position moves by exactly how far the first of them that is still there moved. A list that has
 * been scrolled since (by the person, by the engine's own anchoring, by a scroll that was asked for)
 * is not corrected: the row moved because the list did, and a correction would take the scroll
 * back. A change below the row moves nothing.
 *
 * A row that is in view and goes (an invitation that was accepted, an attempt that was removed) is
 * not made up for: what is after it stays where it was and what is above it comes into view. The
 * person was looking at what is after it, and it is what stays.
 *
 * At the top of the list nothing is anchored: a row that arrives there is simply the first, which is
 * where a person who has not scrolled expects it.
 */

import { useEffect, type RefObject } from 'react'

/** How far a list is scrolled before something above it is something to keep in place. */
const SCROLLED = 8

/** What may be the row that is kept: what a list is made of, and the headings between its parts. */
const ROWS = '.m-row, .sw-heading, .sw-attempt, .m-filters, .m-empty'

/** The nearest scrolling area of a list on the phone. */
const SCROLLER = '.m-main'

/** Rows in view, where each was drawn, and where the list was scrolled to when they were taken. */
interface Kept {
  readonly rows: readonly { readonly row: Element; readonly top: number }[]
  readonly scrolled: number
}

/** How many rows in view are remembered, so that one that is replaced leaves another to go by. */
const REMEMBERED = 4

/** Keeps the first rows in view of the list `content` holds where they are while the list changes. */
export function useKeepPlace(content: RefObject<HTMLElement | null>): void {
  useEffect(() => {
    const element = content.current
    const scroller = element?.closest<HTMLElement>(SCROLLER) ?? null
    if (element === null || scroller === null) return

    // The first rows in view, each with where it is drawn from the top of the scrolling area (so the
    // area itself moving, a bar above it changing height, is not the list moving), and the position
    // the list was scrolled to when they were taken.
    let kept: Kept | null = null

    const take = () => {
      kept = null
      if (scroller.scrollTop <= SCROLLED) return
      const edge = scroller.getBoundingClientRect().top
      const rows: { row: Element; top: number }[] = []
      for (const row of element.querySelectorAll(ROWS)) {
        const box = row.getBoundingClientRect()
        if (box.height > 0 && box.bottom > edge + 1) rows.push({ row, top: box.top - edge })
        if (rows.length === REMEMBERED) break
      }
      if (rows.length > 0) kept = { rows, scrolled: scroller.scrollTop }
    }

    const restore = () => {
      const before = kept
      if (before !== null && scroller.scrollTop === before.scrolled) {
        // The first of the rows that is still there is the one to go by.
        const still = before.rows.find(({ row }) => row.isConnected)
        if (still !== undefined) {
          const by = still.row.getBoundingClientRect().top - scroller.getBoundingClientRect().top - still.top
          if (Math.abs(by) > 0.5) scroller.scrollTop += by
        }
      }
      take()
    }

    take()
    scroller.addEventListener('scroll', take, { passive: true })
    // Markup that changes is read after it did and before it is drawn; a box that changes size
    // without a change of markup (the text size, a font arriving) is read as it does.
    const marking = new MutationObserver(restore)
    marking.observe(element, { childList: true, subtree: true })
    const sizing = typeof ResizeObserver === 'undefined' ? null : new ResizeObserver(restore)
    sizing?.observe(element)
    return () => {
      scroller.removeEventListener('scroll', take)
      marking.disconnect()
      sizing?.disconnect()
    }
  }, [content])
}
