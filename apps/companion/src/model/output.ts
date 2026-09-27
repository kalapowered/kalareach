/**
 * A session's retained output, as the host keeps it, read a page at a time.
 *
 * `history.page` answers with raw bytes from a cursor, bounded by a size the reader names. The
 * bytes are what the session wrote: UTF-8 text broken wherever a page ends, with the escape
 * sequences a terminal acts on between the words. This window holds a bounded run of consecutive
 * pages, moves towards older output or newer output a page at a time, and lets pages go from the
 * far end so it never holds more than its bound. It decodes the pages in order, so a character or
 * an escape sequence that a page boundary cuts in two is read whole, and it shows what the session
 * printed rather than what it asked a terminal to do: colours, titles, cursor moves and clipboard
 * writes are left out, a carriage return starts a new line, and nothing is ever acted on.
 *
 * Where the host no longer keeps output, the page says so and the window keeps what it said.
 */

import type { HistoryGap } from '@kalareach/protocol'

/** How many bytes one read asks for. */
export const OUTPUT_PAGE_BYTES = 64 * 1024

/** The most bytes the window holds at once. */
export const OUTPUT_WINDOW_BYTES = 512 * 1024

/** A cursor past any a host can reach: a read from it answers where the output ends now. */
export const PAST_THE_END = '18446744073709551615'

/** One page of retained output. */
export interface OutputPage {
  /** The cursor its first byte is at. */
  readonly from: string
  /** The cursor after its last byte. */
  readonly next: string
  readonly bytes: Uint8Array
}

/** A bounded run of consecutive pages, and what the host said about the output around it. */
export interface OutputWindow {
  /** Consecutive pages, oldest first. */
  readonly pages: readonly OutputPage[]
  /** The oldest cursor the host still kept when it last answered. */
  readonly oldest: string | null
  /** Where the output ended when the host last answered. */
  readonly end: string | null
  /** What the host said it no longer keeps, when a read asked for it. */
  readonly gap: HistoryGap | null
  /** Whether the reader is at the live end, where new output is read as it comes. */
  readonly following: boolean
  /** The page the reader is looking at and how far its top is from the top of the view. */
  readonly anchor: { readonly from: string; readonly offset: number } | null
}

/** A window that has read nothing yet. */
export function emptyOutput(): OutputWindow {
  return { pages: [], oldest: null, end: null, gap: null, following: true, anchor: null }
}

/** How many bytes the window holds. */
function held(pages: readonly OutputPage[]): number {
  return pages.reduce((total, page) => total + page.bytes.length, 0)
}

/** Whether the window reaches the oldest output the host keeps. */
export function atOldest(window: OutputWindow): boolean {
  const first = window.pages[0]
  return first !== undefined && window.oldest !== null && BigInt(first.from) <= BigInt(window.oldest)
}

/** Whether the window reaches where the output ended when the host last answered. */
export function atEnd(window: OutputWindow): boolean {
  const last = window.pages.at(-1)
  return last !== undefined && window.end !== null && BigInt(last.next) >= BigInt(window.end)
}

/** Records what one answer said about the output as a whole. */
function heard(
  window: OutputWindow,
  answer: { readonly oldest: string; readonly end: string | null; readonly gap: HistoryGap | null }
): OutputWindow {
  const end =
    answer.end === null
      ? window.end
      : window.end === null || BigInt(answer.end) > BigInt(window.end)
        ? answer.end
        : window.end
  return { ...window, oldest: answer.oldest, end, gap: answer.gap ?? window.gap }
}

/**
 * The window after a page older than its first. A page that does not end where the first begins
 * is not the next one along, and changes nothing. Pages go from the newest end while the window
 * holds more than `bound` bytes, so the reader there is no longer at the live end.
 */
export function withOlder(
  window: OutputWindow,
  page: OutputPage,
  answer: { readonly oldest: string; readonly gap: HistoryGap | null },
  bound: number = OUTPUT_WINDOW_BYTES
): OutputWindow {
  const first = window.pages[0]
  if (first !== undefined && page.next !== first.from) return window
  if (page.bytes.length === 0) return heard(window, { ...answer, end: null })
  let pages = [page, ...window.pages]
  let dropped = false
  while (pages.length > 1 && held(pages) > bound) {
    pages = pages.slice(0, -1)
    dropped = true
  }
  return {
    ...heard(window, { ...answer, end: null }),
    pages,
    following: dropped ? false : window.following
  }
}

/**
 * The window after a page newer than its last, or its first page. A page that does not begin where
 * the last ends is not the next one along, and changes nothing, unless the host said why: it no
 * longer keeps what came after the window's last page, and answered from where its output now
 * begins. Everything the window holds is older than that, and the host keeps none of it, so the
 * window starts again at the page, with what the host said it let go. Pages go from the oldest end
 * while the window holds more than `bound` bytes.
 */
export function withNewer(
  window: OutputWindow,
  page: OutputPage,
  answer: { readonly oldest: string; readonly end: string; readonly gap: HistoryGap | null },
  bound: number = OUTPUT_WINDOW_BYTES
): OutputWindow {
  const last = window.pages.at(-1)
  if (last !== undefined && page.from !== last.next) {
    if (answer.gap === null || BigInt(page.from) <= BigInt(last.next)) return window
    const again = heard({ ...window, pages: [], anchor: null }, answer)
    return page.bytes.length === 0 ? again : { ...again, pages: [page] }
  }
  if (page.bytes.length === 0) return heard(window, answer)
  let pages = [...window.pages, page]
  while (pages.length > 1 && held(pages) > bound) pages = pages.slice(1)
  return { ...heard(window, answer), pages }
}

/** Records where the reader is, and whether they are at the live end. */
export function placed(
  window: OutputWindow,
  following: boolean,
  anchor: OutputWindow['anchor']
): OutputWindow {
  return { ...window, following, anchor: following ? null : anchor }
}

/**
 * Reads retained output as the text it printed.
 *
 * It keeps its place between pages: a UTF-8 sequence or an escape sequence that ends in the next
 * page is finished there. Printable text, tabs and line ends are kept; every escape sequence and
 * every other control is left out; a carriage return that is not part of a line end starts a new
 * line, so a line the session wrote over itself reads as each version it wrote.
 */
export class OutputReader {
  readonly #text = new TextDecoder('utf-8', { fatal: false })
  #escape: 'none' | 'escape' | 'csi' | 'string' | 'string-escape' | 'charset' = 'none'
  #returned = false

  /** The text in `bytes`, continuing from whatever the previous call left unfinished. */
  read(bytes: Uint8Array): string {
    const decoded = this.#text.decode(bytes, { stream: true })
    let out = ''
    for (const character of decoded) {
      const code = character.codePointAt(0) ?? 0
      switch (this.#escape) {
        case 'escape':
          if (character === '[') this.#escape = 'csi'
          else if (character === ']' || character === 'P' || character === 'X' || character === '^' || character === '_') {
            this.#escape = 'string'
          } else if ('()*+-./#%'.includes(character)) this.#escape = 'charset'
          else this.#escape = 'none'
          continue
        case 'csi':
          // Parameters and intermediates until the final byte.
          if (code >= 0x40 && code <= 0x7e) this.#escape = 'none'
          continue
        case 'string':
          // An operating-system command or a device control string runs to BEL or ST.
          if (code === 0x07) this.#escape = 'none'
          else if (code === 0x1b) this.#escape = 'string-escape'
          continue
        case 'string-escape':
          this.#escape = character === '\\' ? 'none' : 'string'
          continue
        case 'charset':
          this.#escape = 'none'
          continue
        case 'none':
          break
      }
      if (code === 0x1b) {
        this.#escape = 'escape'
        continue
      }
      if (this.#returned) {
        this.#returned = false
        // A carriage return and a line feed are one line end; a lone return starts another line.
        out += '\n'
        if (character === '\n') continue
      }
      if (character === '\r') {
        this.#returned = true
        continue
      }
      if (character === '\n' || character === '\t') {
        out += character
        continue
      }
      if (code < 0x20 || code === 0x7f || (code >= 0x80 && code <= 0x9f)) continue
      out += character
    }
    return out
  }
}

/**
 * Each page's text, read in order from the first page of the window.
 *
 * The first page may begin partway through a character or an escape sequence the window no longer
 * holds; the bytes of a character cut there are left out rather than shown as another.
 */
export function textOfPages(pages: readonly OutputPage[]): readonly string[] {
  const reader = new OutputReader()
  return pages.map((page, index) => {
    if (index > 0) return reader.read(page.bytes)
    let start = 0
    // UTF-8 continuation bytes at the very start belong to a character the window does not hold.
    while (start < page.bytes.length && start < 3 && ((page.bytes[start] ?? 0) & 0xc0) === 0x80) start += 1
    return reader.read(page.bytes.subarray(start))
  })
}
