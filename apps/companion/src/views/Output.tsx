/**
 * A session's retained output: what it wrote, as the host keeps it, read a page at a time.
 *
 * The view opens at the live end and keeps up with new output while the reader stays there. A
 * reader who scrolls up reads older pages, and scrolling back down reads newer ones; the window
 * holds a bounded run of pages and lets pages go from the far end, and the page the reader is
 * looking at stays where it is on the screen as pages come and go. A change of view and back
 * returns the reader to the same place. Where the host no longer keeps output, the view says so in
 * the host's terms rather than showing a shorter history as if it were all there was.
 *
 * A live session's output is read from its own worker and an ended one's from the host's archive,
 * by native code, with the same method and the same answer.
 */

import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState, type ReactNode } from 'react'

import type { HistoryGapCause, HistoryPageResult } from '@kalareach/protocol'
import { base64UrlToBytes } from '@kalareach/protocol'

import { Banner, Button } from '../components/ui'
import { readOnCadence } from '../app/cadence'
import { AGENT_READ_CADENCE_MS } from '../app/agent'
import { useApp, useSession } from '../app/state'
import { failureMessage } from '../host/port'
import { ask } from '../mobile/model/call'
import {
  atEnd,
  emptyOutput,
  OUTPUT_PAGE_BYTES,
  OUTPUT_WINDOW_BYTES,
  PAST_THE_END,
  placed,
  textOfPages,
  withNewer,
  withOlder,
  type OutputPage,
  type OutputWindow
} from '../model/output'

/** How close to an edge of the window a scroll must come before the next page is read. */
const NEAR_EDGE_PX = 120

/** Why the host no longer keeps output, in words. */
const GAP_WORDS: Readonly<Record<HistoryGapCause, string>> = {
  retention: 'it was older than the host keeps output for',
  host_capacity: 'the host reached the most output it keeps for all its sessions',
  session_capacity: 'this session reached the most output the host keeps for one session',
  spool_unavailable: 'the host could not write it to disk, so it kept only the most recent output',
  archive_incomplete: 'the host holds no record of it'
}

/** A page as the window holds it. */
function pageOf(result: HistoryPageResult): OutputPage {
  return {
    from: result.from_cursor,
    next: result.next_cursor,
    bytes: base64UrlToBytes(result.bytes)
  }
}

/** The larger of two cursors. */
const max = (a: bigint, b: bigint) => (a > b ? a : b)

/**
 * The most answers one span is read in. A host answers short where its memory begins or a segment
 * ends, a few times in one page at most; a host that went on answering short for ever still ends
 * the read.
 */
const MAX_SPAN_ANSWERS = 16

/** A run of output read in one or more answers, and what the host said about the output. */
interface Span {
  readonly page: OutputPage
  readonly oldest: string
  readonly gap: HistoryGapResult
}

type HistoryGapResult = HistoryPageResult['gap']

/** One session's retained output. */
export function RetainedOutput({
  sessionId,
  pageBytes = OUTPUT_PAGE_BYTES,
  windowBytes = OUTPUT_WINDOW_BYTES,
  cadenceMs = AGENT_READ_CADENCE_MS
}: {
  readonly sessionId: string
  /** How many bytes one read asks for. */
  readonly pageBytes?: number
  /** The most bytes the window holds. */
  readonly windowBytes?: number
  /** How long after one read at the live end the next starts. */
  readonly cadenceMs?: number
}): ReactNode {
  const { port, sessions } = useApp()
  const { state, update } = useSession(sessionId)
  const output = state.output
  const scroller = useRef<HTMLDivElement | null>(null)
  const [failure, setFailure] = useState<string | null>(null)
  // The window as the reads below see it, which is the store's own: a read that answers after
  // another changed it builds on what is there now.
  const now = useCallback(() => sessions.get(sessionId).output, [sessions, sessionId])
  // Where the reader was before pages came or went, restored once they have been laid out.
  const keep = useRef<{ readonly from: string; readonly offset: number } | null>(null)
  // One read at a time.
  const reading = useRef(false)
  // Where the reader is now, kept as they scroll and recorded as they leave.
  const position = useRef<OutputWindow['anchor']>(null)
  const [initial] = useState(() => output)

  const change = useCallback(
    (next: (window: OutputWindow) => OutputWindow) => {
      update((session) => {
        const window = next(session.output)
        return window === session.output ? session : { ...session, output: window }
      })
    },
    [update]
  )

  const page = useCallback(
    (from: string, bytes: bigint) =>
      ask(() =>
        port.historyPage({
          session_id: sessionId,
          from_cursor: from,
          max_bytes: String(bytes < 1n ? 1n : bytes)
        })
      ),
    [port, sessionId]
  )

  /**
   * Reads the output from `from` up to `upTo`. A host stops an answer short where its memory
   * begins, so the read goes on from where each answer ended until it reaches `upTo`, the host has
   * nothing more, or the host answers from somewhere else. The first answer may begin later than
   * asked, where the host's output now begins, with what it let go; it then carries as many bytes
   * as were asked for from there, which can run past `upTo`, and what runs past is not kept.
   */
  const span = useCallback(
    async (from: bigint, upTo: bigint): Promise<Span> => {
      /** An answer's bytes, cut at `upTo`, and the cursor after them. */
      const within = (answer: HistoryPageResult): { bytes: Uint8Array; next: bigint } => {
        const bytes = base64UrlToBytes(answer.bytes)
        const start = BigInt(answer.from_cursor)
        const room = upTo > start ? Number(upTo - start) : 0
        return bytes.length > room
          ? { bytes: bytes.subarray(0, room), next: start + BigInt(room) }
          : { bytes, next: BigInt(answer.next_cursor) }
      }
      const first = await page(String(from), upTo - from)
      const opening = within(first)
      const parts = [opening.bytes]
      let at = opening.next
      let last = first
      for (let answers = 1; at < upTo && answers < MAX_SPAN_ANSWERS; answers += 1) {
        const more = await page(String(at), upTo - at)
        const next = within(more)
        if (BigInt(more.from_cursor) !== at || next.bytes.length === 0) break
        parts.push(next.bytes)
        at = next.next
        last = more
      }
      const joined = new Uint8Array(parts.reduce((total, each) => total + each.length, 0))
      let offset = 0
      for (const each of parts) {
        joined.set(each, offset)
        offset += each.length
      }
      return {
        page: { from: first.from_cursor, next: String(at), bytes: joined },
        oldest: last.oldest_retained_cursor,
        gap: first.gap ?? last.gap
      }
    },
    [page]
  )

  /** Runs one read, unless one is on its way, and says what the host refused. */
  const run = useCallback((read: () => Promise<void>): Promise<void> => {
    if (reading.current) return Promise.resolve()
    reading.current = true
    return read()
      .then(() => {
        setFailure(null)
      })
      .catch((error: unknown) => {
        setFailure(failureMessage(error))
      })
      .finally(() => {
        reading.current = false
      })
  }, [])

  /** Finds where the output ends now, and reads the page before it. */
  const openAtEnd = useCallback(
    () =>
      run(async () => {
        const probe = await page(PAST_THE_END, 1n)
        const end = BigInt(probe.from_cursor)
        const oldest = BigInt(probe.oldest_retained_cursor)
        const from = max(oldest, end - BigInt(pageBytes))
        const last = await span(from, end)
        change((window) =>
          window.pages.length > 0
            ? window
            : withNewer(
                { ...emptyOutput(), end: String(end) },
                last.page,
                { oldest: last.oldest, end: last.page.next, gap: last.gap },
                windowBytes
              )
        )
      }),
    [run, page, span, change, pageBytes, windowBytes]
  )

  /** Reads the page before the window's first. */
  const readOlder = useCallback(
    () =>
      run(async () => {
        const window = now()
        const first = window.pages[0]
        if (first === undefined || reachedStart(window)) return
        const upTo = BigInt(first.from)
        // Asked from before what the host keeps, the host answers from where its output now
        // begins and says what it let go and why; the span reads on from there to the window.
        const from = max(0n, upTo - BigInt(pageBytes))
        const answer = await span(from, upTo)
        const scroll = scroller.current
        const anchor = scroll === null ? null : anchorOf(scroll)
        if (anchor !== null) keep.current = anchor
        change((held) =>
          BigInt(answer.page.next) === upTo
            ? withOlder(held, answer.page, { oldest: answer.oldest, gap: answer.gap }, windowBytes)
            : { ...held, oldest: answer.oldest, gap: answer.gap ?? held.gap }
        )
      }),
    [run, span, change, now, pageBytes, windowBytes]
  )

  /** Reads the page after the window's last, or from where the output ended when it holds none. */
  const readNewer = useCallback(
    () =>
      run(async () => {
        const window = now()
        const from = window.pages.at(-1)?.next ?? window.end
        if (from === null) return
        const answer = await page(from, BigInt(pageBytes))
        const scroll = scroller.current
        const anchor = scroll === null ? null : anchorOf(scroll)
        if (anchor !== null && !now().following) keep.current = anchor
        change((held) =>
          withNewer(
            held,
            pageOf(answer),
            {
              oldest: answer.oldest_retained_cursor,
              end: answer.next_cursor,
              gap: answer.gap
            },
            windowBytes
          )
        )
      }),
    [run, page, change, now, pageBytes, windowBytes]
  )

  // Opening: at the live end the first time, and where the reader left it on a return.
  useEffect(() => {
    if (now().pages.length === 0) void openAtEnd()
  }, [openAtEnd, now])

  // At the live end, new output is read as it comes, a session that has written nothing yet
  // included.
  useEffect(() => {
    const cadence = readOnCadence(async () => {
      const window = now()
      if (window.end === null || !window.following) return
      await readNewer()
    }, cadenceMs)
    cadence.now()
    return cadence.stop
  }, [readNewer, now, cadenceMs])

  // A return puts the reader back where they were; the live end keeps up with what arrives.
  useLayoutEffect(() => {
    const element = scroller.current
    position.current = initial.anchor
    if (element === null || initial.following || initial.anchor === null) return
    const block = element.querySelector<HTMLElement>(`[data-from="${initial.anchor.from}"]`)
    if (block !== null) element.scrollTop = block.offsetTop - initial.anchor.offset
  }, [initial])

  useLayoutEffect(() => {
    const element = scroller.current
    if (element === null) return
    const held = keep.current
    if (held !== null) {
      keep.current = null
      const block = element.querySelector<HTMLElement>(`[data-from="${held.from}"]`)
      if (block !== null) element.scrollTop = block.offsetTop - held.offset
      return
    }
    if (output.following) element.scrollTop = element.scrollHeight
  }, [output.pages, output.following])

  // Leaving records where the reader was, in the session's own store.
  useEffect(
    () => () => {
      const anchor = position.current
      change((window) => placed(window, window.following, anchor))
    },
    [change]
  )

  const onScroll = () => {
    const element = scroller.current
    if (element === null) return
    const window = now()
    const bottom = element.scrollHeight - element.scrollTop - element.clientHeight
    const following = bottom < 4 && atEnd(window)
    position.current = following ? null : anchorOf(element)
    if (following !== window.following) change((held) => placed(held, following, position.current))
    if (element.scrollTop < NEAR_EDGE_PX) void readOlder()
    else if (bottom < NEAR_EDGE_PX && !atEnd(window)) void readNewer()
  }

  const texts = useMemo(() => textOfPages(output.pages), [output.pages])
  const loaded = output.pages.length > 0 || output.end !== null
  const empty = loaded && output.pages.length === 0
  const lost = output.gap !== null && (empty || reachedStart(output))
  const cause = output.gap?.cause ?? null

  return (
    <div className="retained-output" data-testid="retained-output">
      {failure !== null ? (
        <Banner
          tone="warning"
          title="This session's output could not be read"
          detail={failure}
          action={
            <Button
              onClick={() => {
                void (output.pages.length === 0 ? openAtEnd() : readOlder())
              }}
            >
              Try again
            </Button>
          }
        />
      ) : null}
      <div
        className="output-scroll"
        ref={scroller}
        onScroll={onScroll}
        data-testid="output-scroll"
        data-following={output.following ? 'true' : 'false'}
        tabIndex={0}
        aria-label="What this session wrote"
      >
        {lost ? (
          <p className="small faint output-edge" data-testid="output-gap">
            Output before this is not kept
            {cause === null ? '.' : `: ${GAP_WORDS[cause]}.`}
          </p>
        ) : null}
        {!loaded ? <p className="small faint output-edge">Reading this session’s output…</p> : null}
        {empty ? (
          <p className="small faint output-edge" data-testid="output-empty">
            The host keeps nothing this session wrote.
          </p>
        ) : null}
        {output.pages.map((each, index) => (
          <pre className="output-page" key={each.from} data-from={each.from}>
            {texts[index]}
          </pre>
        ))}
      </div>
    </div>
  )
}

/**
 * Whether the window begins where the host's output does: at the first byte the session wrote, or
 * at the end of what the host said it no longer keeps.
 */
function reachedStart(window: OutputWindow): boolean {
  const first = window.pages[0]
  if (first === undefined) return true
  if (BigInt(first.from) === 0n) return true
  return window.gap !== null && BigInt(first.from) <= BigInt(window.gap.to_cursor)
}

/** The page the reader is looking at, and how far its top is from the top of the view. */
function anchorOf(element: HTMLElement): { readonly from: string; readonly offset: number } | null {
  for (const block of element.querySelectorAll<HTMLElement>('[data-from]')) {
    if (block.offsetTop + block.offsetHeight > element.scrollTop) {
      const from = block.dataset.from
      if (from !== undefined) return { from, offset: block.offsetTop - element.scrollTop }
    }
  }
  return null
}
