/**
 * One raw terminal view of a session, from the moment its pane shows until it is left.
 *
 * Native code holds the view: its link to the session, its attachment and its screen. This holds
 * what the page draws from it. Each state is kept with the view and the session it came from and
 * shown only there, so a state that arrives late for a view the page has left is never shown in
 * another. The last complete screen is kept while the view waits for the next, so a buffer switch
 * or a zoom step changes nothing on screen until the new one is whole.
 *
 * The desktop's terminal and the phone's each draw through this, so both views open, wait, end and
 * open again the same way and say the same things.
 */

import { useCallback, useEffect, useRef, useState } from 'react'

import {
  failureMessage,
  type HostPort,
  type TerminalGrid,
  type TerminalScreen,
  type TerminalView,
  type TerminalViewState
} from '../host/port'
import { SLOW_MS } from './modes'

/** What the page draws of one view. */
export interface TerminalViewing {
  /** The view's newest state, or null while it attaches. */
  readonly state: TerminalViewState | null
  /** The last complete screen of this session, kept while the view waits and after it ends. */
  readonly frame: TerminalScreen | null
  /** Whether the view has waited without a complete screen long enough to say so. */
  readonly slow: boolean
  /** Reports the page's grid. A grid equal to the one last reported sends nothing. */
  readonly resize: (grid: TerminalGrid) => void
  /** Opens the view again after it has ended. */
  readonly again: () => void
}

/** The grid a view opens at when its surface cannot be measured yet. */
export const FALLBACK_GRID: TerminalGrid = { columns: 80, rows: 24 }

/** One opening of a view: what the page last reported, and the view once native code holds it. */
interface Opening {
  grid: TerminalGrid
  view: TerminalView | null
  /** Whether the page measured a grid before the view was held, which goes once it is. */
  owed: boolean
}

function sameGrid(one: TerminalGrid, other: TerminalGrid): boolean {
  return one.columns === other.columns && one.rows === other.rows
}

/**
 * Opens a view of `sessionId` at the grid `measure` gives, while `showing` holds, and closes it when
 * the pane is left, the session changes or the port does.
 */
export function useTerminalView(
  port: HostPort,
  sessionId: string,
  measure: () => TerminalGrid,
  showing = true
): TerminalViewing {
  const [attempt, setAttempt] = useState(0)
  // Each state with the opening it came from: the session and the attempt.
  const [held, setHeld] = useState<{
    readonly sessionId: string
    readonly attempt: number
    readonly stamp: number
    readonly state: TerminalViewState
  } | null>(null)
  const [framed, setFramed] = useState<{
    readonly sessionId: string
    readonly screen: TerminalScreen
  } | null>(null)
  const [slowStamp, setSlowStamp] = useState(0)
  const stamps = useRef(0)
  const opening = useRef<Opening | null>(null)
  const measuring = useRef(measure)
  useEffect(() => {
    measuring.current = measure
  }, [measure])

  const state = held?.sessionId === sessionId && held.attempt === attempt ? held.state : null
  const stamp = held?.sessionId === sessionId && held.attempt === attempt ? held.stamp : 0
  const frame = framed?.sessionId === sessionId ? framed.screen : null

  useEffect(() => {
    if (!showing) return
    let current = true
    const open: Opening = { grid: measuring.current(), view: null, owed: false }
    opening.current = open
    port
      .openTerminalView(sessionId, open.grid, (next) => {
        if (!current) return
        stamps.current += 1
        setHeld({ sessionId, attempt, stamp: stamps.current, state: next })
        if (next.state === 'showing') setFramed({ sessionId, screen: next.screen })
      })
      .then(
        (view) => {
          if (!current) {
            void view.close()
            return
          }
          open.view = view
          if (open.owed) void view.resize(open.grid)
        },
        (failure: unknown) => {
          if (!current) return
          stamps.current += 1
          setHeld({
            sessionId,
            attempt,
            stamp: stamps.current,
            state: { state: 'ended', reason: failureMessage(failure) }
          })
        }
      )
    return () => {
      current = false
      if (opening.current === open) opening.current = null
      // A view still opening is closed when its open answers, above.
      if (open.view !== null) void open.view.close()
      // What this opening said ends with it: the next one starts from attaching. Its last frame is
      // kept, as the session's, until the next one has a screen of its own.
      setHeld(null)
    }
  }, [port, sessionId, attempt, showing])

  const resize = useCallback((grid: TerminalGrid) => {
    const open = opening.current
    if (open === null || sameGrid(open.grid, grid)) return
    open.grid = grid
    if (open.view === null) {
      open.owed = true
      return
    }
    void open.view.resize(grid)
  }, [])

  const again = useCallback(() => {
    setAttempt((count) => count + 1)
  }, [])

  // A view that has ended opens again when the page hears the host connection come back. A view
  // that is attached is left alone: its link to the session does not go through that connection.
  const ended = state?.state === 'ended'
  const endedNow = useRef(ended)
  useEffect(() => {
    endedNow.current = ended
  }, [ended])
  useEffect(() => {
    let stopped = false
    let stop: (() => void) | null = null
    void port
      .onConnection((connection) => {
        if (connection.connected && endedNow.current) setAttempt((count) => count + 1)
      })
      .then(
        (unlisten) => {
          if (stopped) unlisten()
          else stop = unlisten
        },
        () => undefined
      )
    return () => {
      stopped = true
      stop?.()
    }
  }, [port])

  // Between a reset and the next complete screen the last frame stays as drawn, and the view says
  // it is waiting only once it has waited a moment: a buffer switch or a zoom step would otherwise
  // flicker a line of words in and out.
  const waitingOnAFrame = state?.state === 'waiting' && frame !== null
  useEffect(() => {
    if (!waitingOnAFrame) return
    const timer = setTimeout(() => {
      setSlowStamp(stamp)
    }, SLOW_MS)
    return () => {
      clearTimeout(timer)
    }
  }, [waitingOnAFrame, stamp])

  return {
    state,
    frame,
    slow: waitingOnAFrame && slowStamp === stamp,
    resize,
    again
  }
}
