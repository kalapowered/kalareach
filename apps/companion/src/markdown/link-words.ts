/**
 * The words of a link, as the phone's press reads them and as the test harness lists them.
 *
 * The words are the rectangles of the lines of each text node in the link's label, and the border box of
 * each replaced element in it (an imported image). The box of an element that holds text is no part of
 * them: an inline box drawn around a label's text has a border area that covers the blank room at the ends
 * of its lines, and a tap in that room is on no word. A range over the whole label gives that box beside the
 * lines, so each text node is read with a range of its own.
 *
 * The cost of that: the padding that an inline element puts round its text (inline code) is no part of the
 * words. The reads are one range for each text node of the label and one box for each replaced element, all
 * of them after one layout, and the walk of the label's nodes reads no layout.
 */

import type { Rect } from './link-target'

/** The elements that the engine draws as one box with no text of the page's inside: their border box is words. */
const REPLACED = 'img, svg, video, canvas, object, embed, iframe'

/** The rectangles of a link's words, one for each line of each text node of its label and one for each replaced element in it. */
export function wordsOf(link: Element): Rect[] {
  const words: Rect[] = []
  const lines = document.createRange()
  const read = (parent: Node): void => {
    for (let node = parent.firstChild; node !== null; node = node.nextSibling) {
      if (node instanceof Text) {
        lines.selectNodeContents(node)
        for (const rect of Array.from(lines.getClientRects())) keep(words, rect)
      } else if (node instanceof Element) {
        if (node.matches(REPLACED)) for (const rect of Array.from(node.getClientRects())) keep(words, rect)
        else read(node)
      }
    }
  }
  read(link.querySelector('.md-link-label') ?? link)
  return words
}

/** Adds a rectangle that has a size. */
function keep(words: Rect[], rect: DOMRect): void {
  if (rect.width > 0 && rect.height > 0) words.push({ left: rect.left, top: rect.top, right: rect.right, bottom: rect.bottom })
}
