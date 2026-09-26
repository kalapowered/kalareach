/**
 * The raw terminal view.
 *
 * It draws the session's screen as native code holds it for this view: the part of the live screen
 * the host drew for the view's grid, as cells. Each piece of a line is a box of its own at its
 * canonical cells, in the session's palette (`frame.ts`), so a glyph the browser draws wider than
 * its cells, joins to its neighbour or lays out right to left stays inside its own cells, and the
 * view runs no terminal state machine: nothing the session printed can make it answer.
 *
 * Two modes, and the wheel belongs to whichever one is active. In control mode the application
 * inside the terminal gets the wheel, unchanged. In view mode the person is reading the screen: the
 * wheel and a drag move the window across the session, up into its history and down its live
 * screen, a zoom gesture makes the text larger or smaller, and the program gets nothing. A drag in
 * view mode moves the window, so text is selected in control mode. Switching to control mode brings
 * a window in the history back to the live screen.
 *
 * The frame is drawn where the moves the page made and native code has not yet settled will put
 * the window (`pan.ts`), and a drag follows the pointer to the pixel; nothing animates.
 *
 * The view holds no geometry claim. Leaving it for the conversation closes it, which releases what
 * it held and nothing of anyone else's.
 */

import {
  useCallback,
  useEffect,
  useLayoutEffect,
  useRef,
  useState,
  type CSSProperties,
  type ReactNode
} from 'react'

import type { PaletteState } from '@kalareach/protocol'

import { Badge, Button, Segmented } from '../components/ui'
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
  selectionOf,
  type PlacedCursor
} from './frame'
import {
  ATTACHING,
  describeProvenance,
  placeOf,
  presentationOf,
  routeWheel,
  WAITING,
  warningsOf,
  zoomBy,
  ZOOM_DEFAULT_INDEX,
  ZOOM_STEPS,
  type ViewMode
} from './modes'
import {
  beginDrag,
  dragTo,
  releaseDrag,
  WHEEL_AT_REST,
  wheelTurn,
  type Cells,
  type Drag,
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

/** Whether a movement moves anything. */
function moves(cells: Cells): boolean {
  return cells.across !== 0 || cells.down !== 0
}

/** One drag of the window in progress: its session, its pointer, the drag, and its cell. */
interface Dragging {
  readonly sessionId: string
  readonly pointer: number
  readonly drag: Drag
  readonly cell: Cell
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
  shift
}: {
  readonly screen: TerminalScreen
  readonly cell: Cell
  /** How far the frame is drawn from its place, in pixels. */
  readonly shift: Point
}): ReactNode {
  const palette = screen.palette
  const cursor = placedCursor(screen)
  const columns = count(screen.window.columns)
  const rows = count(screen.window.rows)
  const pieces = placedPieces(screen)
  const selection = selectionOf(palette)
  return (
    <div
      className="kr-terminal-grid"
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
      <style data-terminal-selection="">
        {`.kr-terminal-grid ::selection { background-color: ${selection.background}; color: ${selection.foreground}; }`}
      </style>
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
  onLeave
}: {
  readonly sessionId: string
  readonly onLeave: () => void
}): ReactNode {
  const { port } = useApp()
  const host = useRef<HTMLDivElement | null>(null)
  const surface = useRef<HTMLDivElement | null>(null)
  const probe = useRef<HTMLSpanElement | null>(null)
  const [mode, setMode] = useState<ViewMode>('control')
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

  const { state, frame, slow, resize, again, shift, moving, movingSlow, roomNow, pan, live } =
    useTerminalView(port, sessionId, measure)
  const drawnCell = cell ?? UNMEASURED_CELL

  // The drag in progress, and the part of it not sent, as drawn. A wheel's part short of a cell is
  // carried to its next turn.
  const dragging = useRef<Dragging | null>(null)
  const [dragged, setDragged] = useState<{ readonly sessionId: string; readonly at: Point } | null>(null)
  const wheelRest = useRef<WheelRest>(WHEEL_AT_REST)
  // The newest way to move the window, for the wheel's own listener and the end of a drag.
  const panning = useRef({ pan, roomNow, cell: drawnCell })
  useEffect(() => {
    panning.current = { pan, roomNow, cell: drawnCell }
  })

  /**
   * Ends the drag in progress. A release sends only the cells rounding adds; any other end drops
   * the part not sent at once. The moves already sent wait for their screen either way.
   */
  const endDrag = useCallback((released: Point | null) => {
    const current = dragging.current
    dragging.current = null
    setDragged(null)
    if (current === null || released === null) return
    const room = panning.current.roomNow()
    if (room === null) return
    const rounding = releaseDrag(current.drag, released, current.cell, room)
    if (moves(rounding)) panning.current.pan(rounding)
  }, [])

  // A drag belongs to its session and its mode: an ended view, another session or control mode draws
  // none, and the next pointer event of the old one is ignored.
  const ended = state?.state === 'ended'
  const draggable = mode === 'view' && !ended
  const drawnDrag = draggable && dragged?.sessionId === sessionId ? dragged.at : AT_REST
  useEffect(
    () => () => {
      dragging.current = null
      wheelRest.current = WHEEL_AT_REST
    },
    [sessionId]
  )

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

  // The wheel is read here rather than through a React handler, so that in view mode it can be
  // cancelled before the page scrolls. In control mode it must reach the program unchanged, so this
  // neither cancels it nor stops it; in view mode this is the owner and cancels it.
  useEffect(() => {
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
        setWheelToApplication((count) => count + 1)
        void port
          .terminalInput({ session_id: sessionId, wheel: { lines: outcome.lines } })
          .catch(() => {
            // A failed forward is a transport failure; the banner above already says so.
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
  }, [mode, port, sessionId])

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
    x: drawnDrag.x - shift.across * drawnCell.width,
    y: drawnDrag.y - shift.down * drawnCell.height
  }

  return (
    <section className="raw-terminal" data-testid="raw-terminal" data-mode={mode}>
      <header className="terminal-heading">
        <span className="row">
          <Segmented
            label="Pointer mode"
            value={mode}
            options={[
              { value: 'control', label: 'Control' },
              { value: 'view', label: 'View' }
            ]}
            onChange={(next) => {
              endDrag(null)
              // Control mode shows the program's live screen: a window in the history comes back.
              if (next === 'control') live()
              setMode(next)
            }}
          />
          <span className="small faint">
            {mode === 'control'
              ? 'The program in this terminal gets the wheel and the keys.'
              : 'Scroll or drag to move around the session. The program gets nothing.'}
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
          <Button data-testid="attach-again" onClick={again}>
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
            if (!draggable || event.button !== 0 || event.isPrimary === false) return
            if (dragging.current?.sessionId === sessionId) return
            event.preventDefault()
            event.currentTarget.setPointerCapture(event.pointerId)
            dragging.current = {
              sessionId,
              pointer: event.pointerId,
              drag: beginDrag({ x: event.clientX, y: event.clientY }),
              cell: drawnCell
            }
          }}
          onPointerMove={(event) => {
            const current = dragging.current
            if (current === null || event.pointerId !== current.pointer) return
            if (!draggable || current.sessionId !== sessionId) {
              dragging.current = null
              return
            }
            const at = { x: event.clientX, y: event.clientY }
            // A zoom step changes the cell: the drag goes on from here, keeping what it sent.
            if (current.cell.width !== drawnCell.width || current.cell.height !== drawnCell.height) {
              dragging.current = { ...current, drag: beginDrag(at), cell: drawnCell }
              setDragged(null)
              return
            }
            const room = roomNow()
            if (room === null) return
            const element = event.currentTarget
            const step = dragTo(current.drag, at, current.cell, room, {
              width: element.clientWidth || (frame?.window.columns ?? 0) * current.cell.width,
              height: element.clientHeight || (frame?.window.rows ?? 0) * current.cell.height
            })
            if (moves(step.send)) pan(step.send)
            dragging.current = { ...current, drag: step.drag }
            setDragged({ sessionId, at: step.offset })
          }}
          onPointerUp={(event) => {
            if (event.pointerId !== dragging.current?.pointer) return
            endDrag({ x: event.clientX, y: event.clientY })
          }}
          onPointerCancel={(event) => {
            if (event.pointerId === dragging.current?.pointer) endDrag(null)
          }}
          onLostPointerCapture={(event) => {
            if (event.pointerId === dragging.current?.pointer) endDrag(null)
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
          {frame === null ? null : <Grid screen={frame} cell={drawnCell} shift={drawnShift} />}
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
