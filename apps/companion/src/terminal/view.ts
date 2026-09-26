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
 *
 * It also keeps the moves the page made that native code has not yet said are settled, in order,
 * and draws the last frame shifted to where they will put the window (`pan.ts`). Native code says a
 * move is settled only with a screen that holds it, so the shift is dropped exactly as the frame
 * that holds the move replaces the one it was drawn over.
 */

import { useCallback, useEffect, useRef, useState } from 'react'

import {
  failureMessage,
  type HostPort,
  type TerminalGrid,
  type TerminalMove,
  type TerminalRoom,
  type TerminalScreen,
  type TerminalView,
  type TerminalViewState
} from '../host/port'
import { SLOW_MS } from './modes'
import { replay, roomLeft, STILL, within, type Cells } from './pan'

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
  /** Where the frame is drawn from its own place: moved by the moves not yet settled. */
  readonly shift: Cells
  /** Whether moves wait for the screen that settles them. */
  readonly moving: boolean
  /** Whether moves have waited long enough, without a break, to say so. */
  readonly movingSlow: boolean
  /** How far the window can move each way right now, once every unsettled move is applied. */
  readonly roomNow: () => TerminalRoom | null
  /** Moves the window by whole cells, as far as its room lets it, and says how far it asked for. */
  readonly pan: (cells: Cells) => Cells
  /** Brings a window in the history back to the live screen, behind the moves already made. */
  readonly live: () => void
}

/** The grid a view opens at when its surface cannot be measured yet. */
export const FALLBACK_GRID: TerminalGrid = { columns: 80, rows: 24 }

/** One opening of a view: what the page last reported, and the view once native code holds it. */
interface Opening {
  grid: TerminalGrid
  view: TerminalView | null
  /** Whether the page measured a grid before the view was held, which goes once it is. */
  owed: boolean
  /** The session and the attempt it opened for. */
  readonly sessionId: string
  readonly attempt: number
  /** The number of this opening's last move. */
  number: number
  /** Its moves native code has not yet said are settled, in order. */
  pending: TerminalMove[]
  /** When its moves began to wait without a break, while any wait. */
  since: number | null
}

/** No moves waiting. */
const NO_MOVES: readonly TerminalMove[] = []

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
  // The moves waiting for their screen, with the opening they belong to and when they began to
  // wait without a break; the list itself lives with its opening.
  const [waitingMoves, setWaitingMoves] = useState<{
    readonly sessionId: string
    readonly attempt: number
    readonly moves: readonly TerminalMove[]
    readonly since: number | null
  } | null>(null)
  const [movingSlowSince, setMovingSlowSince] = useState<number | null>(null)
  const ownMoves = waitingMoves?.sessionId === sessionId && waitingMoves.attempt === attempt
  const pending = ownMoves ? waitingMoves.moves : NO_MOVES
  const movingSince = ownMoves ? waitingMoves.since : null

  const state = held?.sessionId === sessionId && held.attempt === attempt ? held.state : null
  const stamp = held?.sessionId === sessionId && held.attempt === attempt ? held.stamp : 0
  const frame = framed?.sessionId === sessionId ? framed.screen : null
  const frameNow = useRef(frame)
  useEffect(() => {
    frameNow.current = frame
  }, [frame])

  /** Keeps `moves` as the opening's waiting moves, and when they began to wait without a break. */
  const keepMoves = useCallback((open: Opening, moves: TerminalMove[]) => {
    open.since = moves.length === 0 ? null : open.pending.length === 0 ? Date.now() : open.since
    open.pending = moves
    setWaitingMoves({ sessionId: open.sessionId, attempt: open.attempt, moves, since: open.since })
  }, [])

  useEffect(() => {
    if (!showing) return
    let current = true
    const open: Opening = {
      grid: measuring.current(),
      view: null,
      owed: false,
      sessionId,
      attempt,
      number: 0,
      pending: [],
      since: null
    }
    opening.current = open
    port
      .openTerminalView(sessionId, open.grid, (next) => {
        if (!current) return
        stamps.current += 1
        setHeld({ sessionId, attempt, stamp: stamps.current, state: next })
        if (next.state === 'showing') {
          // Held at once as well, so a move made before the next render measures from this frame.
          frameNow.current = next.screen
          setFramed({ sessionId, screen: next.screen })
        }
        // What native code has settled goes, with the frame that holds it; an end settles all.
        const settled = next.state === 'ended' ? Infinity : Number(next.settled)
        const left = open.pending.filter((move) => move.number > settled)
        if (left.length !== open.pending.length) keepMoves(open, left)
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
      // kept, as the session's, until the next one has a screen of its own. Its moves go with it:
      // native code closed the view that would have settled them.
      setHeld(null)
      setWaitingMoves(null)
    }
  }, [port, sessionId, attempt, showing, keepMoves])

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

  /** Sends one move as the opening's next, and keeps it until native code says it is settled. */
  const send = useCallback((open: Opening, view: TerminalView, move: (number: number) => TerminalMove) => {
    open.number += 1
    const made = move(open.number)
    keepMoves(open, [...open.pending, made])
    void view.move(made).catch(() => {
      // A failed call is a view that has gone; its end settles every move.
    })
  }, [keepMoves])

  const pan = useCallback(
    (cells: Cells): Cells => {
      const open = opening.current
      const shown = frameNow.current
      if (open?.view == null || shown === null) return STILL
      const asked = within(cells, roomLeft(shown, open.pending))
      if (asked.across === 0 && asked.down === 0) return STILL
      send(open, open.view, (number) => ({ number, across: asked.across, down: asked.down }))
      return asked
    },
    [send]
  )

  const roomNow = useCallback((): TerminalRoom | null => {
    const open = opening.current
    const shown = frameNow.current
    return open === null || shown === null ? null : roomLeft(shown, open.pending)
  }, [])

  const live = useCallback(() => {
    const open = opening.current
    if (open?.view == null) return
    send(open, open.view, (number) => ({ number, live: true }))
  }, [send])

  // Moves that wait say so only once they have waited a moment without a break: a state that
  // arrives meanwhile does not start the wait again.
  const moving = pending.length > 0
  useEffect(() => {
    if (movingSince === null) return
    const timer = setTimeout(
      () => {
        setMovingSlowSince(movingSince)
      },
      Math.max(0, movingSince + SLOW_MS - Date.now())
    )
    return () => {
      clearTimeout(timer)
    }
  }, [movingSince])

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
    again,
    shift: frame === null ? STILL : replay(frame, pending),
    moving,
    movingSlow: moving && movingSince !== null && movingSlowSince === movingSince,
    roomNow,
    pan,
    live
  }
}
