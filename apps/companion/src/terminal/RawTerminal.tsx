/**
 * The raw terminal view.
 *
 * It draws the session's screen as native code holds it for this view: the part of the live screen
 * the host drew for the view's grid, as cells. Each piece of a line is a box of its own at its
 * canonical cells, in the session's palette (`frame.ts`), so a glyph the browser draws wider than
 * its cells, joins to its neighbour or lays out right to left stays inside its own cells, and the
 * view runs no terminal state machine: nothing the session printed can make it answer.
 *
 * Two modes, and the wheel belongs to whichever one is active. A view opens in view mode, where the
 * person is reading the screen: the wheel and a drag move the window across the session, up into its
 * history and down its live screen, a zoom gesture makes the text larger or smaller, and the program
 * gets nothing. Control mode is the person's own take of the session's input, labelled as that, and
 * brings a window in the history back to the live screen: the program then gets the wheel, turned at
 * the session's cell under the pointer while it reports the mouse, and nothing otherwise. A drag in
 * view mode moves the window, so text is selected in control mode. Looking around gives control back
 * at once, and a view whose control the session ends says why.
 *
 * While the view controls the program, the program's keyboard (`keyboard.ts`) sits at the cursor's
 * cell, where an input method opens its candidates, next after the mode button in keyboard order. A
 * click on the terminal that selects nothing puts the focus in it, and the terminal shows a focus
 * ring while it has it. What an input method composes is drawn at the cursor's cell in the session's
 * colours until it is committed. When control ends with the focus in it, the focus goes to the mode
 * button, which takes control again; so does the focus of Attach again, unless a pointer pressed it,
 * once the view is open again.
 *
 * The frame is drawn where the moves the page made and native code has not yet settled will put
 * the window (`pan.ts`), and a drag follows the pointer to the pixel; nothing animates. Every change
 * of the view a gesture was made in ends it at the change itself: another opening, mode or life
 * drops a drag and a wheel's part of a cell, and the pointer's remaining events are ignored; a zoom
 * step begins a drag again from where the pointer is. A change that comes back to where it was is
 * still a change. Four labelled buttons move the window a page at a time, for a keyboard and for a
 * screen reader.
 *
 * The view holds no geometry claim. Leaving it for the conversation closes it, which releases what
 * it held and nothing of anyone else's.
 */

import {
  useCallback,
  useEffect,
  useId,
  useLayoutEffect,
  useRef,
  useState,
  type CSSProperties,
  type ReactNode
} from 'react'
import { flushSync } from 'react-dom'

import type { PaletteState } from '@kalareach/protocol'

import { Badge, Button } from '../components/ui'
import { useApp } from '../app/state'
import type { TerminalGrid, TerminalScreen } from '../host/port'
import { styleOf } from './cells'
import {
  backgroundOf,
  copiedText,
  count,
  cursorColourOf,
  foregroundOf,
  placedCursor,
  placedPieces,
  selectionRule,
  type PlacedCursor
} from './frame'
import { useFocusWhenControlEnds, useOwnControl } from './focus'
import { cellUnder, wheelPixels, wheelTurns } from './input'
import { useProgramKeyboard } from './keyboard'
import { applePlatform, SENTINEL } from './keys'
import {
  ASKING,
  ATTACHING,
  describeProvenance,
  modeOf,
  placeOf,
  presentationOf,
  routeWheel,
  WAITING,
  warningsOf,
  wheelHeldBack,
  zoomBy,
  ZOOM_DEFAULT_INDEX,
  ZOOM_STEPS
} from './modes'
import {
  beginDrag,
  dragTo,
  releaseDrag,
  restartDrag,
  restWithin,
  WHEEL_AT_REST,
  wheelTurn,
  type Cells,
  type HeldDrag,
  type Point,
  type WheelRest
} from './pan'
import { FALLBACK_GRID, useTerminalView } from './view'

const FONT_FAMILY = 'ui-monospace, SFMono-Regular, Consolas, monospace'

/** The type size before zoom, in pixels. */
const BASE_FONT_SIZE = 12

/**
 * The surface's padding. The grid sits inside it, on an element of its own, so the grid is
 * measured from the space it actually has.
 */
const SURFACE_INSET = 12

/** How many cells the probe that measures a cell holds: its width over this is a cell's. */
const PROBE_CELLS = 10

/** One cell's size in pixels. */
interface Cell {
  readonly width: number
  readonly height: number
}

/** One cell at the probe's type size, or null where nothing is laid out. */
function cellOf(probe: HTMLSpanElement | null): Cell | null {
  const box = probe?.getBoundingClientRect()
  return box !== undefined && box.width > 0 && box.height > 0
    ? { width: box.width / PROBE_CELLS, height: Math.ceil(box.height) }
    : null
}

/** The cell a grid is laid out with before its first measure, which a page with no layout keeps. */
const UNMEASURED_CELL: Cell = { width: 8, height: 16 }

/** The frame where it rests. */
const AT_REST: Point = { x: 0, y: 0 }

/** The four buttons that move the window a page each way, and the room each one needs. */
const PAGE_MOVES = [
  { name: 'up', label: 'Up', across: 0, down: -1, limit: 'up' },
  { name: 'down', label: 'Down', across: 0, down: 1, limit: 'down' },
  { name: 'left', label: 'Left', across: -1, down: 0, limit: 'left' },
  { name: 'right', label: 'Right', across: 1, down: 0, limit: 'right' }
] as const

/** Whether a movement moves anything. */
function moves(cells: Cells): boolean {
  return cells.across !== 0 || cells.down !== 0
}


/** How every piece's box is drawn: at its cells, its text laid out on its own and cut at its edges. */
const PIECE: CSSProperties = {
  position: 'absolute',
  overflow: 'hidden',
  whiteSpace: 'pre',
  unicodeBidi: 'isolate',
  direction: 'ltr'
}

/** The session's cursor, in its steady shape, over the cell it is in. */
function cursorStyle(cursor: PlacedCursor, cell: Cell, palette: PaletteState): CSSProperties {
  const colour = cursorColourOf(palette)
  const edge =
    cursor.shape === 'underline'
      ? { borderBottom: `2px solid ${colour}` }
      : cursor.shape === 'bar'
        ? { borderLeft: `2px solid ${colour}` }
        : { border: `1px solid ${colour}` }
  return {
    position: 'absolute',
    left: cursor.column * cell.width,
    top: cursor.line * cell.height,
    width: cell.width,
    height: cell.height,
    boxSizing: 'border-box',
    pointerEvents: 'none',
    ...edge
  }
}

/**
 * The screen as the view draws it: each piece a box of its own at its cells, and the cursor. A copy
 * of a selection gives the pieces it touches as lines of text laid out by their cells.
 */
function Grid({
  screen,
  cell,
  shift,
  gridRef
}: {
  readonly screen: TerminalScreen
  readonly cell: Cell
  /** How far the frame is drawn from its place, in pixels. */
  readonly shift: Point
  /** Where the grid is, for finding the session's cell under the pointer. */
  readonly gridRef: React.RefObject<HTMLDivElement | null>
}): ReactNode {
  const palette = screen.palette
  const cursor = placedCursor(screen)
  const columns = count(screen.window.columns)
  const rows = count(screen.window.rows)
  const pieces = placedPieces(screen)
  const name = useId()
  return (
    <div
      ref={gridRef}
      data-terminal-grid={name}
      data-testid="terminal-grid"
      data-columns={columns}
      data-rows={rows}
      onCopy={(event) => {
        const selection = window.getSelection()
        if (selection === null || selection.isCollapsed) return
        const boxes = event.currentTarget.querySelectorAll('[data-testid="terminal-piece"]')
        const selected = pieces.filter((_, index) => {
          const box = boxes[index]
          return box !== undefined && selection.containsNode(box, true)
        })
        if (selected.length === 0) return
        event.clipboardData.setData('text/plain', copiedText(selected))
        event.preventDefault()
      }}
      style={{
        position: 'relative',
        width: columns * cell.width,
        height: rows * cell.height,
        lineHeight: `${cell.height}px`,
        color: foregroundOf(palette),
        transform: `translate(${shift.x}px, ${shift.y}px)`
      }}
    >
      {pieces.map((piece) => (
        <span
          key={`${piece.line}:${piece.column}`}
          data-testid="terminal-piece"
          data-line={piece.line}
          data-column={piece.column}
          data-cells={piece.cells}
          style={{
            ...PIECE,
            left: piece.column * cell.width,
            top: piece.line * cell.height,
            width: piece.cells * cell.width,
            height: cell.height,
            ...styleOf(piece.rendition, palette)
          }}
        >
          {piece.text}
        </span>
      ))}
      {/* Selected text takes the session's selection colours, as the terminal it came from shows it. */}
      <style data-terminal-selection="">{selectionRule(name, palette)}</style>
      {cursor === null ? null : (
        <span
          data-testid="terminal-cursor"
          data-line={cursor.line}
          data-column={cursor.column}
          data-shape={cursor.shape}
          style={cursorStyle(cursor, cell, palette)}
        />
      )}
    </div>
  )
}

/** The raw view of one session. */
export function RawTerminal({
  sessionId,
  onLeave,
  onFrame
}: {
  readonly sessionId: string
  readonly onLeave: () => void
  /** Told each screen the view draws, as a recording keeps it. */
  readonly onFrame?: (screen: TerminalScreen) => void
}): ReactNode {
  const { port } = useApp()
  const host = useRef<HTMLDivElement | null>(null)
  const surface = useRef<HTMLDivElement | null>(null)
  const probe = useRef<HTMLSpanElement | null>(null)
  const grid = useRef<HTMLDivElement | null>(null)
  const [zoom, setZoom] = useState(ZOOM_DEFAULT_INDEX)
  const [cell, setCell] = useState<Cell | null>(null)
  const [wheelToApplication, setWheelToApplication] = useState(0)
  const fontSize = BASE_FONT_SIZE * (ZOOM_STEPS[zoom] ?? 1)

  // A cell is measured at the current type size before the grid is painted, so a zoom step lays
  // the last frame out again at once, from its top-left corner.
  useLayoutEffect(() => {
    const measured = cellOf(probe.current)
    setCell((current) =>
      current?.width === measured?.width && current?.height === measured?.height ? current : measured
    )
  }, [fontSize])

  /**
   * The grid the surface holds at the current cell size. The view opens before the measured cell
   * has reached its state, so a missing one is read from the probe at once: the first grid the host
   * is given is the surface's own.
   */
  const measure = useCallback((): TerminalGrid => {
    const element = host.current
    const current = cell ?? cellOf(probe.current)
    if (element === null || current === null) return FALLBACK_GRID
    const columns = Math.floor(element.clientWidth / current.width)
    const rows = Math.floor(element.clientHeight / current.height)
    return columns > 0 && rows > 0 ? { columns, rows } : FALLBACK_GRID
  }, [cell])

  const {
    state,
    frame,
    slow,
    resize,
    again,
    openingKey,
    shift,
    room,
    moving,
    movingSlow,
    roomNow,
    pan,
    control,
    takeControl,
    lookAround,
    toProgram,
    controlTake,
    refuse,
    unsent
  } = useTerminalView(port, sessionId, measure)

  // Each screen the view draws is what a recording of it keeps.
  useEffect(() => {
    if (frame !== null) onFrame?.(frame)
  }, [frame, onFrame])
  const drawnCell = cell ?? UNMEASURED_CELL
  const ended = state?.state === 'ended'
  const mode = modeOf(control)
  const draggable = mode === 'view' && !ended
  const controlling = control?.state === 'controlling' && !ended
  const [apple] = useState(() => applePlatform(navigator.userAgent))
  const { attach, composing, focus } = useProgramKeyboard({ controlTake, toProgram, refuse, apple })
  const modeButtonId = useId()
  const sentenceId = useId()
  const attachAgainId = useId()
  const attachAgain = useOwnControl(attachAgainId, ended)

  // Focus that the program's keyboard or the mode button held when control or the view ends goes to
  // the mode button, which takes control again, or once the view has ended to Attach again: a field
  // that has gone, or a button that is disabled, is no place to leave it. The same goes for Attach
  // again, unless a pointer pressed it, once the view is open again.
  useFocusWhenControlEnds({
    state: ended ? 'ended' : (control?.state ?? 'none'),
    heldFor: (element) =>
      element?.matches('[data-program-keyboard]') === true ||
      element?.id === modeButtonId ||
      attachAgain.held(element),
    destination: () => document.getElementById(ended ? attachAgainId : modeButtonId)
  })

  // The drag in progress, a wheel's part of a cell carried to its next move of the window, and a
  // wheel's part of a row carried to its next turn of the program's wheel. The part of the drag not
  // sent is drawn on a layer of its own, which only the drag and the changes below touch.
  const dragging = useRef<HeldDrag | null>(null)
  const dragLayer = useRef<HTMLDivElement | null>(null)
  const wheelRest = useRef<WheelRest>(WHEEL_AT_REST)
  const turnRest = useRef(0)
  // The newest way to move the window and to reach the program, for the wheel's own listener: kept
  // at each commit, so the wheel never measures a turn in a cell the view has left, nor sends one to
  // a program the view no longer controls.
  const panning = useRef({ pan, roomNow, cell: drawnCell, frame, control, toProgram })
  useLayoutEffect(() => {
    panning.current = { pan, roomNow, cell: drawnCell, frame, control, toProgram }
  })

  /** Draws the part of the drag not sent. */
  const drawDrag = (at: Point) => {
    const layer = dragLayer.current
    if (layer === null) return
    layer.style.transform = at.x === 0 && at.y === 0 ? '' : `translate(${at.x}px, ${at.y}px)`
  }

  /** Ends the drag in progress, sending nothing: its part not sent is dropped. */
  const dropDrag = () => {
    dragging.current = null
    drawDrag(AT_REST)
  }

  /**
   * Sends the whole cells a drag has crossed, and draws the frame at its new place before the next
   * paint, so the frame and the drag's part on its own layer never show out of step. Drawing it may
   * draw a change of the view that was waiting, whose effects end or begin again the drag, so a
   * handler calls this last, once the drag and its part are stored.
   */
  const sendDragged = (cells: Cells) => {
    flushSync(() => {
      pan(cells)
    })
  }

  // Every change of the view a gesture was made in ends it here, at the change itself: another
  // opening, another mode, or the view's end. A change that comes back to where it was is a change
  // too, so nothing made before it can count again. A pointer still down sends nothing more.
  useLayoutEffect(() => {
    dragging.current = null
    wheelRest.current = WHEEL_AT_REST
    turnRest.current = 0
    const layer = dragLayer.current
    if (layer !== null) layer.style.transform = ''
  }, [openingKey, mode, ended])
  // A zoom step changes the cell: a drag begins again from where the pointer is, and a wheel's part
  // of the old cell is dropped.
  const cellWidth = drawnCell.width
  const cellHeight = drawnCell.height
  useLayoutEffect(() => {
    const held = dragging.current
    if (held !== null) dragging.current = restartDrag(held, { width: cellWidth, height: cellHeight })
    wheelRest.current = WHEEL_AT_REST
    turnRest.current = 0
    const layer = dragLayer.current
    if (layer !== null) layer.style.transform = ''
  }, [cellWidth, cellHeight])
  // The program starting or stopping to read the wheel takes the part of a row carried towards it.
  const programWheel = frame?.wheel ?? null
  useLayoutEffect(() => {
    turnRest.current = 0
  }, [programWheel])

  // A limit the window reaches takes the wheel's part of a cell toward it as the room is drawn,
  // whatever reached it, so the window leaving the limit before the next turn does not bring it back.
  const roomUp = room?.up ?? null
  const roomDown = room?.down ?? null
  const roomToLeft = room?.left ?? null
  const roomToRight = room?.right ?? null
  useLayoutEffect(() => {
    if (roomUp === null || roomDown === null || roomToLeft === null || roomToRight === null) return
    wheelRest.current = restWithin(wheelRest.current, {
      up: roomUp,
      down: roomDown,
      left: roomToLeft,
      right: roomToRight
    })
  }, [roomUp, roomDown, roomToLeft, roomToRight])

  // The grid goes to the host whenever the surface or the cell size changes: at once, and then as
  // the surface is resized.
  useEffect(() => {
    resize(measure())
    const element = surface.current
    if (!element || typeof ResizeObserver === 'undefined') return
    const observer = new ResizeObserver(() => {
      resize(measure())
    })
    observer.observe(element)
    return () => {
      observer.disconnect()
    }
  }, [resize, measure])

  // The wheel is read here rather than through a React handler, so that it can be cancelled before
  // the page scrolls. In control mode it is the program's: turned at the session's cell under the
  // pointer, once for each row of pixels, while the program reads it, and cancelled then; left to the
  // page while it does not. In view mode this is the owner and cancels it. The listener is replaced
  // as a change of mode is committed, so no turn after it is routed by the mode before.
  useLayoutEffect(() => {
    const element = host.current
    if (!element) return
    const onWheel = (event: WheelEvent) => {
      const outcome = routeWheel(mode, {
        deltaX: event.deltaX,
        deltaY: event.deltaY,
        zoomGesture: event.ctrlKey,
        sideways: event.shiftKey
      })
      if (outcome.kind === 'application') {
        const { cell: at, frame: shown, control: now, toProgram: send } = panning.current
        if (now?.state !== 'controlling' || shown === null || shown.wheel !== 'reaches') return
        event.preventDefault()
        const turned = wheelTurns(turnRest.current, wheelPixels(event, at.height, count(shown.window.rows)), at.height)
        turnRest.current = turned.rest
        if (turned.turns === 0) return
        const drawnGrid = grid.current
        const under =
          drawnGrid === null
            ? null
            : cellUnder({ x: event.clientX, y: event.clientY }, drawnGrid, element, shown, at)
        if (under === null) return
        setWheelToApplication((sent) => sent + 1)
        void send({
          kind: 'wheel',
          column: under.column,
          line: under.line,
          turns: turned.turns,
          shift: event.shiftKey,
          alt: event.altKey,
          control: event.ctrlKey
        }).catch(() => {
          // A refusal here is control that has just ended, which the view's state says.
        })
        return
      }
      event.preventDefault()
      if (outcome.kind === 'zoom') {
        setZoom((current) => zoomBy(current, outcome.steps))
        return
      }
      const { pan: send, roomNow: roomOf, cell: at } = panning.current
      const room = roomOf()
      if (room === null) return
      // A wheel that counts in lines or pages is measured in rows and columns of this grid.
      const line = event.deltaMode === 1
      const page = event.deltaMode === 2
      const rows = Math.max(1, Math.floor(element.clientHeight / at.height))
      const columns = Math.max(1, Math.floor(element.clientWidth / at.width))
      const turned = wheelTurn(
        wheelRest.current,
        {
          across: outcome.across * (line ? at.width : page ? at.width * columns : 1),
          down: outcome.down * (line ? at.height : page ? at.height * rows : 1)
        },
        at,
        room
      )
      wheelRest.current = turned.rest
      if (moves(turned.send)) send(turned.send)
    }
    element.addEventListener('wheel', onWheel, { capture: true, passive: false })
    return () => {
      element.removeEventListener('wheel', onWheel, { capture: true })
    }
  }, [mode])

  const attachment = state !== null && state.state !== 'ended' ? state.attachment : null
  const presentation = attachment === null ? null : presentationOf(attachment)
  const waiting = state?.state === 'waiting'
  // What the position slot says: that the view is waiting, once it or its moves have waited, or
  // where the window is.
  const position =
    (waiting && (frame === null || slow)) || movingSlow
      ? WAITING
      : frame === null
        ? null
        : placeOf(frame)
  const drawnShift: Point = {
    x: -shift.across * drawnCell.width,
    y: -shift.down * drawnCell.height
  }

  // What the mode does, in the words of its state, or why control last ended; while the view
  // controls the program, why the last input did not reach it, until one does.
  const sentence =
    control === null || control.state === 'watching'
      ? (control?.ended ?? 'Scroll or drag to move around the session. The program gets nothing.')
      : control.state === 'taking'
        ? ASKING
        : (unsent ??
          `Your keys go to the program; Control-Tab moves on. ${
            (frame === null ? null : wheelHeldBack(frame.wheel)) ?? 'The program gets the wheel.'
          }`)
  // Where the program's keyboard and what an input method composes sit: at the cursor's cell, as
  // the frame is drawn, or at the first cell while the view has no cursor to show.
  const cursorAt = frame === null ? null : placedCursor(frame)
  const keyboardAt: CSSProperties = {
    left: (cursorAt?.column ?? 0) * drawnCell.width + drawnShift.x,
    top: (cursorAt?.line ?? 0) * drawnCell.height + drawnShift.y,
    width: drawnCell.width,
    height: drawnCell.height
  }

  return (
    <section className="raw-terminal" data-testid="raw-terminal" data-mode={mode}>
      <header className="terminal-heading">
        <span className="row">
          <Badge tone={control?.state === 'controlling' ? 'accent' : 'neutral'} data-testid="terminal-mode">
            {control?.state === 'controlling' ? 'Control' : control?.state === 'taking' ? 'Taking control…' : 'View'}
          </Badge>
          {/* One button whose words change, so the focus stays on it through the take. */}
          <Button
            id={modeButtonId}
            disabled={control === null}
            onClick={() => {
              if (mode === 'view') takeControl()
              else lookAround()
            }}
          >
            {mode === 'view' ? 'Take control' : 'Look around'}
          </Button>
          <span className="small faint" role="status" id={sentenceId} data-testid="terminal-mode-sentence">
            {sentence}
          </span>
        </span>
        {frame ? (
          <span className="row">
            <Badge tone="neutral" data-testid="palette-provenance">
              Palette: {describeProvenance(frame.palette.source)}
            </Badge>
            <Badge tone="neutral" data-testid="terminal-size">
              {`${frame.dimensions.columns}×${frame.dimensions.rows}`}
            </Badge>
            {/* Every piece is drawn, cut to its box, so the view leaves nothing blank of its own. */}
            {warningsOf(frame, 0).map((warning) => (
              <Badge key={warning.id} tone="warning" data-testid={warning.id}>
                {warning.words}
              </Badge>
            ))}
          </span>
        ) : null}
      </header>

      {state?.state === 'ended' ? (
        <div className="banner warning row between" role="status" data-testid="terminal-ended">
          <span>{state.reason}</span>
          <Button
            id={attachAgainId}
            data-testid="attach-again"
            onClick={(event) => {
              attachAgain.press(event)
              again()
            }}
          >
            Attach again
          </Button>
        </div>
      ) : null}

      <div
        className="terminal-surface"
        ref={surface}
        data-testid="terminal-surface"
        data-wheel-to-application={wheelToApplication}
        aria-busy={state === null || waiting || moving}
        style={{
          position: 'relative',
          overflow: 'hidden',
          ...(frame ? { background: backgroundOf(frame.palette) } : {})
        }}
      >
        <div
          ref={host}
          onPointerDown={(event) => {
            // A second pointer ends the drag in progress, sending nothing more.
            if (dragging.current !== null) {
              dropDrag()
              return
            }
            if (!draggable || event.button !== 0 || event.isPrimary === false) return
            event.preventDefault()
            event.currentTarget.setPointerCapture(event.pointerId)
            const at = { x: event.clientX, y: event.clientY }
            dragging.current = { pointer: event.pointerId, drag: beginDrag(at), cell: drawnCell, last: at }
          }}
          onPointerMove={(event) => {
            const held = dragging.current
            if (held === null || event.pointerId !== held.pointer) return
            const room = roomNow()
            if (room === null) return
            const at = { x: event.clientX, y: event.clientY }
            const element = event.currentTarget
            const step = dragTo(held.drag, at, held.cell, room, {
              width: element.clientWidth || (frame?.window.columns ?? 0) * held.cell.width,
              height: element.clientHeight || (frame?.window.rows ?? 0) * held.cell.height
            })
            dragging.current = { ...held, drag: step.drag, last: at }
            drawDrag(step.offset)
            if (moves(step.send)) sendDragged(step.send)
          }}
          onPointerUp={(event) => {
            const held = dragging.current
            if (held === null || event.pointerId !== held.pointer) return
            // A release sends only the cells rounding adds.
            dropDrag()
            const room = roomNow()
            if (room === null) return
            const rounding = releaseDrag(held.drag, { x: event.clientX, y: event.clientY }, held.cell, room)
            if (moves(rounding)) sendDragged(rounding)
          }}
          onPointerCancel={(event) => {
            if (event.pointerId === dragging.current?.pointer) dropDrag()
          }}
          onLostPointerCapture={(event) => {
            if (event.pointerId === dragging.current?.pointer) dropDrag()
          }}
          onClick={() => {
            // A click that selects nothing is the person turning to the program; one that selects
            // text leaves the focus where the selection can be copied from.
            if (!controlling) return
            const selection = window.getSelection()
            if (selection === null || selection.isCollapsed) focus()
          }}
          style={{
            position: 'absolute',
            inset: SURFACE_INSET,
            overflow: 'hidden',
            fontFamily: FONT_FAMILY,
            fontSize,
            fontKerning: 'none',
            fontVariantLigatures: 'none',
            // In view mode a drag moves the window: the browser neither selects nor scrolls with it.
            ...(draggable ? { userSelect: 'none', touchAction: 'none' } : {})
          }}
        >
          <span
            ref={probe}
            aria-hidden="true"
            style={{ position: 'absolute', visibility: 'hidden', pointerEvents: 'none', whiteSpace: 'pre' }}
          >
            {'M'.repeat(PROBE_CELLS)}
          </span>
          <div ref={dragLayer}>
            {frame === null ? null : (
              <Grid screen={frame} cell={drawnCell} shift={drawnShift} gridRef={grid} />
            )}
          </div>
          {controlling ? (
            <textarea
              ref={attach}
              className="terminal-keyboard"
              data-program-keyboard=""
              data-testid="terminal-keyboard"
              aria-label="Type to the program"
              aria-describedby={sentenceId}
              rows={1}
              defaultValue={SENTINEL}
              autoCapitalize="off"
              autoComplete="off"
              autoCorrect="off"
              spellCheck={false}
              style={keyboardAt}
            />
          ) : null}
          {controlling && composing ? (
            <span
              className="terminal-composition"
              data-testid="terminal-composition"
              aria-hidden="true"
              style={{
                ...keyboardAt,
                width: 'auto',
                lineHeight: `${drawnCell.height}px`,
                ...(frame === null
                  ? {}
                  : { color: foregroundOf(frame.palette), background: backgroundOf(frame.palette) })
              }}
            >
              {composing}
            </span>
          ) : null}
        </div>
      </div>

      <footer className="terminal-footer between">
        <span className="row wrap small faint">
          {state === null ? (
            <span data-testid="terminal-presentation" data-presentation="attaching">
              {ATTACHING}
            </span>
          ) : presentation ? (
            <span data-testid="terminal-presentation" data-presentation={presentation.state}>
              {presentation.sentence}
            </span>
          ) : null}
          <span data-testid="terminal-position">{position}</span>
        </span>
        <span className="row">
          <span className="row" role="group" aria-label="Move the window">
            {PAGE_MOVES.map((move) => (
              <Button
                key={move.name}
                aria-label={`Move the window ${move.name}`}
                disabled={mode !== 'view' || room === null || room[move.limit] === 0}
                onClick={() => {
                  if (frame === null) return
                  pan({
                    across: move.across * count(frame.window.columns),
                    down: move.down * count(frame.window.rows)
                  })
                }}
              >
                {move.label}
              </Button>
            ))}
          </span>
          <Button
            data-testid="zoom-out"
            disabled={mode !== 'view' || zoom === 0}
            onClick={() => {
              setZoom((current) => zoomBy(current, -1))
            }}
          >
            Smaller
          </Button>
          <Button
            data-testid="zoom-in"
            disabled={mode !== 'view' || zoom === ZOOM_STEPS.length - 1}
            onClick={() => {
              setZoom((current) => zoomBy(current, 1))
            }}
          >
            Larger
          </Button>
          <Button data-testid="release-geometry" onClick={onLeave}>
            Back to the conversation
          </Button>
        </span>
      </footer>
    </section>
  )
}
