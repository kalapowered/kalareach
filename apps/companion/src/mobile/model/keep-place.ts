/**
 * Keeping what a person is reading where it is while the list above it changes.
 *
 * A list that is read again every few seconds can gain a row above the one a person has scrolled to.
 * Chromium moves the scroll position by itself to keep the row in place (scroll anchoring); WebKit
 * does not, and the row under the person's finger jumps. Neither is left to the engine: the first
 * row that is in view is remembered with where it is drawn and where the list was scrolled to, and
 * when the list changes with the scroll position where it was, the scroll position moves by exactly
 * how far that row moved. A list that has been scrolled since (by the person, by the engine's own
 * anchoring, by a scroll that was asked for) is not corrected: the row moved because the list did,
 * and a correction would take the scroll back. A change below the row moves nothing.
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

/** Keeps the first row in view of the list `content` holds where it is while the list changes. */
export function useKeepPlace(content: RefObject<HTMLElement | null>): void {
  useEffect(() => {
    const element = content.current
    const scroller = element?.closest<HTMLElement>(SCROLLER) ?? null
    if (element === null || scroller === null) return

    let kept: { readonly row: Element; readonly top: number; readonly scrolled: number } | null = null

    // The first row whose lower edge is below the top of what is in view, and where it is.
    const take = () => {
      if (scroller.scrollTop <= SCROLLED) {
        kept = null
        return
      }
      const edge = scroller.getBoundingClientRect().top
      kept = null
      for (const row of element.querySelectorAll(ROWS)) {
        const box = row.getBoundingClientRect()
        if (box.height > 0 && box.bottom > edge + 1) {
          kept = { row, top: box.top, scrolled: scroller.scrollTop }
          return
        }
      }
    }

    const restore = () => {
      const before = kept
      if (before !== null && before.row.isConnected && scroller.scrollTop === before.scrolled) {
        const by = before.row.getBoundingClientRect().top - before.top
        if (Math.abs(by) > 0.5) scroller.scrollTop += by
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
