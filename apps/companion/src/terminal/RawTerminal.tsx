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
 * view takes the wheel and zooms with it, and the program gets nothing. The window stays on the
 * live screen, so nothing pans.
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
  count,
  cursorColourOf,
  foregroundOf,
  placedCursor,
  placedPieces,
  type PlacedCursor
} from './frame'
import {
  ATTACHING,
  clipping,
  describeProvenance,
  presentationOf,
  routeWheel,
  WAITING,
  warningsOf,
  zoomBy,
  ZOOM_DEFAULT_INDEX,
  ZOOM_STEPS,
  type ViewMode
} from './modes'
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

/** The cell a grid is laid out with before its first measure, which a page with no layout keeps. */
const UNMEASURED_CELL: Cell = { width: 8, height: 16 }

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

/** The screen as the view draws it: each piece a box of its own at its cells, and the cursor. */
function Grid({ screen, cell }: { readonly screen: TerminalScreen; readonly cell: Cell }): ReactNode {
  const palette = screen.palette
  const cursor = placedCursor(screen)
  const columns = count(screen.window.columns)
  const rows = count(screen.window.rows)
  return (
    <div
      data-testid="terminal-grid"
      data-columns={columns}
      data-rows={rows}
      style={{
        position: 'relative',
        width: columns * cell.width,
        height: rows * cell.height,
        lineHeight: `${cell.height}px`,
        color: foregroundOf(palette)
      }}
    >
      {placedPieces(screen).map((piece) => (
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
    const box = probe.current?.getBoundingClientRect()
    const measured =
      box !== undefined && box.width > 0 && box.height > 0
        ? { width: box.width / PROBE_CELLS, height: Math.ceil(box.height) }
        : null
    setCell((current) =>
      current?.width === measured?.width && current?.height === measured?.height ? current : measured
    )
  }, [fontSize])

  /** The grid the surface holds at the current cell size. */
  const measure = useCallback((): TerminalGrid => {
    const element = host.current
    if (element === null || cell === null) return FALLBACK_GRID
    const columns = Math.floor(element.clientWidth / cell.width)
    const rows = Math.floor(element.clientHeight / cell.height)
    return columns > 0 && rows > 0 ? { columns, rows } : FALLBACK_GRID
  }, [cell])

  const { state, frame, slow, resize, again } = useTerminalView(port, sessionId, measure)

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
        zoomGesture: event.ctrlKey
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
      }
    }
    element.addEventListener('wheel', onWheel, { capture: true, passive: false })
    return () => {
      element.removeEventListener('wheel', onWheel, { capture: true })
    }
  }, [mode, port, sessionId])

  const attachment = state !== null && state.state !== 'ended' ? state.attachment : null
  const presentation = attachment === null ? null : presentationOf(attachment)
  const waiting = state?.state === 'waiting'
  // What the position slot says: that the view is waiting, once it has waited, or that the window
  // shows only part of the session.
  const position =
    waiting && (frame === null || slow) ? WAITING : frame === null ? null : clipping(frame)

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
              setMode(next)
            }}
          />
          <span className="small faint">
            {mode === 'control'
              ? 'The program in this terminal gets the wheel and the keys.'
              : 'Make the text larger or smaller. The program gets nothing.'}
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
        aria-busy={state === null || waiting}
        style={{
          position: 'relative',
          overflow: 'hidden',
          ...(frame ? { background: backgroundOf(frame.palette) } : {})
        }}
      >
        <div
          ref={host}
          style={{
            position: 'absolute',
            inset: SURFACE_INSET,
            overflow: 'hidden',
            fontFamily: FONT_FAMILY,
            fontSize,
            fontKerning: 'none',
            fontVariantLigatures: 'none'
          }}
        >
          <span
            ref={probe}
            aria-hidden="true"
            style={{ position: 'absolute', visibility: 'hidden', pointerEvents: 'none', whiteSpace: 'pre' }}
          >
            {'M'.repeat(PROBE_CELLS)}
          </span>
          {frame === null ? null : <Grid screen={frame} cell={cell ?? UNMEASURED_CELL} />}
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
