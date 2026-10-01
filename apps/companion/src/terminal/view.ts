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
 *
 * And it asks for control of the program and gives it back, numbering each request in the order the
 * person makes them. Until native code has answered the newest, the page shows that request's own
 * state at once: taking control, or watching. It sends the program a wheel turn, a key, text or a
 * paste only while native code says the view controls the program under the newest take, and names
 * that take, so nothing made in one period of control is written in another. Every input of an
 * opening, its takes and releases included, goes to native code one at a time, the next once the
 * last is answered: native code takes each call as a task of its own, so two sent together could
 * reach the view in either order. An input that did not reach the program says why, until the next
 * one that does.
 */

import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react'

import {
  failureCode,
  failureMessage,
  type HostPort,
  type ProgramInput,
  type TerminalControl,
  type TerminalGrid,
  type TerminalInput,
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
  /**
   * Which opening of which session this is. A drag or a wheel's part belongs to one, and ends
   * with it.
   */
  readonly openingKey: string
  /** Where the frame is drawn from its own place: moved by the moves not yet settled. */
  readonly shift: Cells
  /** How far the window can still move each way once those moves are applied, or null with none. */
  readonly room: TerminalRoom | null
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
  /**
   * Whether the view controls the program, as the page shows it: native code's word once it has
   * answered the person's newest request, and that request's own state until then. Null before the
   * first state and once the view has ended.
   */
  readonly control: TerminalControl | null
  /** Takes control: brings a window in the history back to the live screen, and asks for control. */
  readonly takeControl: () => void
  /** Gives control back, and sends the program nothing more from this moment. */
  readonly lookAround: () => void
  /**
   * Sends the program a wheel turn, a key, text or a paste, under the newest take, while the view
   * controls the program; otherwise sends nothing. Rejects with native code's refusal.
   */
  readonly toProgram: (input: ProgramInput) => Promise<void>
  /**
   * The take an input would go under now: the newest, while the view controls the program under it.
   * Null while it does not, when nothing would go.
   */
  readonly controlTake: () => number | null
  /**
   * Says why an input the page itself held back did not reach the program, as a refusal of native
   * code's is said.
   */
  readonly refuse: (words: string) => void
  /**
   * Why the person's last input did not reach the program, while the view still controls it under
   * the take it was made under and no press, repeat, text or paste has reached the program since;
   * null otherwise.
   */
  readonly unsent: string | null
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
  /**
   * Whether the view has ended, by native code's word or because its open was refused: nothing
   * settles a move made after that, and the page opens it again when the host connection returns.
   */
  ended: boolean
  /** The person's newest control request: its number, and whether it takes control. */
  asked: ControlRequest
  /** How many of its inputs native code has not yet answered. */
  unanswered: number
  /** Settles once the last input sent to native code is answered, whatever the answer. */
  sending: Promise<void>
}

/**
 * Sends `input` to `view` once every input the opening sent before it is answered: at once when
 * none waits, so an input goes as soon as the person makes it.
 */
function inTurn(open: Opening, view: TerminalView, input: TerminalInput): Promise<void> {
  const answer = open.unanswered === 0 ? view.input(input) : open.sending.then(() => view.input(input))
  open.unanswered += 1
  open.sending = answer.then(
    () => {
      open.unanswered -= 1
    },
    () => {
      open.unanswered -= 1
    }
  )
  return answer
}

/** One of the person's requests for control, numbered in the order they made them. */
interface ControlRequest {
  readonly number: number
  readonly take: boolean
}

/** Before the person has asked for anything: watching. */
const NOTHING_ASKED: ControlRequest = { number: 0, take: false }

/**
 * What the page shows of control: native code's word once it names the person's newest request, and
 * that request's own state until then.
 */
function shownControl(published: TerminalControl, asked: ControlRequest): TerminalControl {
  if (published.number >= asked.number) return published
  return { number: asked.number, state: asked.take ? 'taking' : 'watching', ended: null }
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
  // The person's newest control request, with the opening it belongs to.
  const [askedControl, setAskedControl] = useState<{
    readonly sessionId: string
    readonly attempt: number
    readonly asked: ControlRequest
  } | null>(null)
  // Why the person's last input did not reach the program, with the opening and the take it was
  // made under.
  const [unsentInput, setUnsentInput] = useState<{
    readonly sessionId: string
    readonly attempt: number
    readonly take: number
    readonly words: string
  } | null>(null)
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
      since: null,
      ended: false,
      asked: NOTHING_ASKED,
      unanswered: 0,
      sending: Promise.resolve()
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
        // What native code has settled goes, with the frame that holds it; an end settles all, and
        // the view takes no move after it.
        if (next.state === 'ended') open.ended = true
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
          open.ended = true
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
      // native code closed the view that would have settled them. Its control goes too: the next
      // opening starts watching.
      setHeld(null)
      setWaitingMoves(null)
      setAskedControl(null)
      setUnsentInput(null)
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
      if (open?.view == null || open.ended || shown === null) return STILL
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
    return open === null || open.ended || shown === null ? null : roomLeft(shown, open.pending)
  }, [])

  const live = useCallback(() => {
    const open = opening.current
    if (open?.view == null || open.ended) return
    send(open, open.view, (number) => ({ number, live: true }))
  }, [send])

  /** Makes the person's next control request, and sends it. */
  const ask = useCallback((take: boolean) => {
    const open = opening.current
    if (open?.view == null || open.ended) return
    const asked = { number: open.asked.number + 1, take }
    open.asked = asked
    setAskedControl({ sessionId: open.sessionId, attempt: open.attempt, asked })
    void inTurn(open, open.view, { kind: take ? 'take' : 'release', number: asked.number }).catch(() => {
      // A failed call is a view that has gone; its end says so.
    })
  }, [])

  const takeControl = useCallback(() => {
    // Control mode shows the program's live screen: a window in the history comes back first.
    live()
    ask(true)
  }, [live, ask])

  const lookAround = useCallback(() => {
    ask(false)
  }, [ask])

  const published = state?.state === 'waiting' || state?.state === 'showing' ? state.control : null
  const asked =
    askedControl?.sessionId === sessionId && askedControl.attempt === attempt ? askedControl.asked : NOTHING_ASKED
  const control = published === null ? null : shownControl(published, asked)
  // Kept at each commit, so no event after it reads the control before it.
  const controlNow = useRef(control)
  useLayoutEffect(() => {
    controlNow.current = control
  }, [control])

  const controlTake = useCallback((): number | null => {
    const open = opening.current
    const shown = controlNow.current
    if (open?.view == null || open.ended || shown?.state !== 'controlling') return null
    return shown.number === open.asked.number && open.asked.take ? open.asked.number : null
  }, [])

  const toProgram = useCallback(
    (input: ProgramInput): Promise<void> => {
      const open = opening.current
      const take = controlTake()
      if (open?.view == null || take === null) return Promise.resolve()
      const answer = inTurn(open, open.view, { ...input, take })
      // An input that reaches the program ends the words of one that did not. Native code writes a
      // press, a repeat, text and a paste whenever it takes them; it can take a release or a wheel
      // turn and write nothing, as for the release of a press it refused, so neither ends them. A
      // refusal of control that has just ended is said by the view's own state; any other refusal
      // says why here.
      const writes = input.kind === 'text' || input.kind === 'paste' || (input.kind === 'key' && input.event !== 'release')
      answer.then(
        () => {
          if (!writes) return
          setUnsentInput((current) =>
            current?.sessionId === open.sessionId && current.attempt === open.attempt ? null : current
          )
        },
        (failure: unknown) => {
          if (failureCode(failure) === 'LEASE_LOST') return
          setUnsentInput({
            sessionId: open.sessionId,
            attempt: open.attempt,
            take,
            words: failureMessage(failure)
          })
        }
      )
      return answer
    },
    [controlTake]
  )

  const refuse = useCallback(
    (words: string) => {
      const open = opening.current
      const take = controlTake()
      if (open === null || take === null) return
      setUnsentInput({ sessionId: open.sessionId, attempt: open.attempt, take, words })
    },
    [controlTake]
  )

  const unsent =
    unsentInput !== null &&
    unsentInput.sessionId === sessionId &&
    unsentInput.attempt === attempt &&
    control?.state === 'controlling' &&
    control.number === unsentInput.take
      ? unsentInput.words
      : null

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
  // The opening records its end when it is published, not when the page has drawn it, so a
  // connection that returns in between is not lost.
  useEffect(() => {
    let stopped = false
    let stop: (() => void) | null = null
    void port
      .onConnection((connection) => {
        if (connection.connected && opening.current?.ended === true) setAttempt((count) => count + 1)
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
    openingKey: `${sessionId}:${attempt}`,
    shift: frame === null ? STILL : replay(frame, pending),
    room: frame === null || state?.state === 'ended' ? null : roomLeft(frame, pending),
    moving,
    movingSlow: moving && movingSince !== null && movingSlowSince === movingSince,
    roomNow,
    pan,
    live,
    control,
    takeControl,
    lookAround,
    toProgram,
    controlTake,
    refuse,
    unsent
  }
}
