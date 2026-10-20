/**
 * The one measure of text that runs out of its box.
 *
 * A box does not say where its text is drawn when the text runs out of it, so a check that reads
 * element boxes passes a long word that spills over a card's edge. This reads the page the way the
 * eye does: the box of every element under a root, and every line of every piece of text, each held
 * to the screen and to the root's own box, and a line of text to the box that lays it out. What lies
 * inside a box that scrolls sideways is meant to lie outside the screen and the root, so it is held
 * to the box that lays it out only.
 */

import type { Page } from '@playwright/test'

/**
 * What is drawn past the sides of the screen or of its own root, for each element that `roots`
 * selects: the boxes of everything under it, and every line of its text. Empty when everything
 * lies inside. A line scrolled out of sight vertically is not a side overrun and is not reported.
 */
export function overrunning(page: Page, roots: string): Promise<string[]> {
  return page.evaluate((selector) => {
    const screen = window.innerWidth
    const label = (text: string | null, fallback: string): string =>
      (text ?? '').replace(/\s+/g, ' ').trim().slice(0, 40) || fallback
    // Text kept for a screen reader is shrunk to a point and clipped: what it would draw is not
    // drawn, so it lies outside nothing.
    const clippedAway = (from: Element | null, root: Element): boolean => {
      for (let each = from; each !== null; each = each === root ? null : each.parentElement) {
        const box = each.getBoundingClientRect()
        if (box.width <= 2 && box.height <= 2 && getComputedStyle(each).overflow !== 'visible') return true
      }
      return false
    }
    // The nearest box that is not part of a line of text, or none when it scrolls sideways: what a
    // scroller holds is meant to lie outside it.
    const laidOutBy = (from: Element | null, root: Element): { left: number; right: number } | undefined => {
      for (let each = from; each !== null; each = each === root ? null : each.parentElement) {
        const style = getComputedStyle(each)
        if (style.display === 'inline' || style.display === 'contents') continue
        if (scrollsSideways(each)) return undefined
        const box = each.getBoundingClientRect()
        return { left: box.left, right: box.right }
      }
      return undefined
    }
    // Whether something lies inside a box that really scrolls sideways, where it is meant to lie
    // outside. A box whose content fits across is not one, whatever it says of its overflow: setting
    // only the vertical overflow makes the horizontal one auto as well.
    const scrollsSideways = (box: Element): boolean => {
      const { overflowX } = getComputedStyle(box)
      return (overflowX === 'auto' || overflowX === 'scroll') && box.scrollWidth > box.clientWidth + 1
    }
    const scrolledInside = (from: Element | null, root: Element): boolean => {
      for (let each = from; each !== null; each = each === root ? null : each.parentElement) {
        if (scrollsSideways(each)) return true
      }
      return false
    }
    const found: string[] = []
    for (const root of document.querySelectorAll(selector)) {
      const card = root.getBoundingClientRect()
      const drawn: {
        left: number
        right: number
        what: string
        within?: { left: number; right: number }
        // True for text inside a box that scrolls sideways: it is meant to lie outside the screen
        // and the root, but not outside the box that holds it.
        scrolled?: boolean
      }[] = []
      for (const element of [root, ...root.querySelectorAll('*')]) {
        const box = element.getBoundingClientRect()
        // An element with no box is not drawn: it has no place to be outside of.
        if (box.width === 0 && box.height === 0) continue
        if (clippedAway(element, root)) continue
        if (element !== root && scrolledInside(element.parentElement, root)) continue
        drawn.push({ left: box.left, right: box.right, what: label(element.textContent, element.tagName) })
      }
      const walk = document.createTreeWalker(root, NodeFilter.SHOW_TEXT)
      for (let node = walk.nextNode(); node !== null; node = walk.nextNode()) {
        if (clippedAway(node.parentElement, root)) continue
        const scrolled = scrolledInside(node.parentElement, root)
        const range = document.createRange()
        range.selectNodeContents(node)
        // The box that lays the text out: a label that runs out of its own button or chip has run
        // out of a box that may still lie inside the root.
        const laid = laidOutBy(node.parentElement, root)
        for (const line of Array.from(range.getClientRects())) {
          if (line.width > 0) {
            drawn.push({
              left: line.left,
              right: line.right,
              what: label(node.textContent, 'text'),
              within: laid,
              scrolled
            })
          }
        }
      }
      for (const one of drawn) {
        if (!one.scrolled && (one.left < -0.5 || one.right > screen + 0.5)) found.push(`${one.what}: past the screen`)
        else if (!one.scrolled && (one.left < card.left - 0.5 || one.right > card.right + 0.5)) {
          found.push(`${one.what}: past its box`)
        } else if (one.within !== undefined && (one.left < one.within.left - 0.5 || one.right > one.within.right + 0.5)) {
          found.push(`${one.what}: past the box that holds it`)
        }
      }
    }
    return found
  }, roots)
}

/**
 * The control for [`overrunning`]: stops the text under each of `roots` from wrapping, so that the
 * layout it measures has text running out of its boxes. A check whose control still reports
 * nothing cannot see the fault it is there to catch.
 */
export async function stopWrapping(page: Page, roots: readonly string[]): Promise<void> {
  const rule = roots.map((root) => `${root}, ${root} *`).join(', ')
  await page.addStyleTag({ content: `${rule} { white-space: nowrap !important }` })
}

/**
 * The words under each of `roots` that a line break has cut in two although the whole word would fit
 * across the root: a column narrower than its text breaks words that were never too long for the
 * card that holds them, and a word wider than the root itself is left out, since nothing can keep it
 * whole. A word is a run of letters and digits between spaces and hyphens, with the punctuation
 * after it; a name or a path with a dot or a slash in it is not one, since it has no place to end a
 * line. A word is cut when the lines it is drawn on number more than one, and its whole width is the
 * sum of its pieces.
 */
export function brokenWords(page: Page, roots: string): Promise<string[]> {
  return page.evaluate((selector) => {
    const found: string[] = []
    for (const root of document.querySelectorAll(selector)) {
      const own = getComputedStyle(root)
      const room =
        root.getBoundingClientRect().width -
        parseFloat(own.paddingLeft) -
        parseFloat(own.paddingRight) -
        parseFloat(own.borderLeftWidth) -
        parseFloat(own.borderRightWidth)
      const walk = document.createTreeWalker(root, NodeFilter.SHOW_TEXT)
      for (let node = walk.nextNode(); node !== null; node = walk.nextNode()) {
        const parent = node.parentElement
        if (parent === null) continue
        const style = getComputedStyle(parent)
        if (style.visibility === 'hidden' || style.display === 'none') continue
        const text = node.textContent ?? ''
        for (const word of text.matchAll(/[^\s\u2010-\u2015-]+/gu)) {
          // Ordinary words only: a name or a path with a dot or a slash in it has no place to end a line.
          if (!/^[\p{L}\p{N}]+[.,;:!?]*$/u.test(word[0])) continue
          const range = document.createRange()
          range.setStart(node, word.index)
          range.setEnd(node, word.index + word[0].length)
          const pieces = Array.from(range.getClientRects()).filter((piece) => piece.width > 0)
          if (pieces.length < 2) continue
          // Two rects on one line are one piece in two boxes; pieces are told apart by their line.
          const lines = new Set(pieces.map((piece) => Math.round(piece.top)))
          if (lines.size < 2) continue
          const whole = pieces.reduce((sum, piece) => sum + piece.width, 0)
          if (whole <= room) found.push(`${word[0]}: cut although ${whole.toFixed(0)} px fits in ${room.toFixed(0)}`)
        }
      }
    }
    return found
  }, roots)
}
