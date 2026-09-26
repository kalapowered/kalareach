/**
 * The raw terminal view.
 *
 * It draws the session's screen as native code holds it for this view: the part of the live screen
 * the host drew for the view's grid, as cells. It writes the renderer only this page's own fixed
 * sequences and each piece's text, so it runs no terminal state machine over the session's output
 * and nothing the session printed can make the renderer answer.
 *
 * Two modes, and the wheel belongs to whichever one is active. In control mode the application
 * inside the terminal gets the wheel, unchanged. In view mode the person is reading the screen: the
 * view takes the wheel and zooms with it, and the program gets nothing. The window stays on the
 * live screen, so nothing pans.
 *
 * The view holds no geometry claim. Leaving it for the conversation closes it, which releases what
 * it held and nothing of anyone else's.
 */

import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react'
import { Terminal } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import '@xterm/xterm/css/xterm.css'

import { Badge, Button, Segmented } from '../components/ui'
import { useApp } from '../app/state'
import type { TerminalGrid } from '../host/port'
import { backgroundOf, paint, themeOf } from './frame'
import {
  ATTACHING,
  clipping,
  describeProvenance,
  presentationOf,
  routeWheel,
  WAITING,
  zoomBy,
  ZOOM_DEFAULT_INDEX,
  ZOOM_STEPS,
  type ViewMode
} from './modes'
import { FALLBACK_GRID, useTerminalView } from './view'

/** The base cell size before zoom. */
const BASE_FONT_SIZE = 12

/**
 * The surface's padding. The renderer sits inside it, on an element of its own, so the grid is
 * measured from the space the renderer actually has.
 */
const SURFACE_INSET = 12

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
  const renderer = useRef<{ readonly terminal: Terminal; readonly fit: FitAddon } | null>(null)
  const [mode, setMode] = useState<ViewMode>('control')
  const [zoom, setZoom] = useState(ZOOM_DEFAULT_INDEX)
  // Which renderer the screen was last drawn into: a new one draws the last frame again at once.
  const [generation, setGeneration] = useState(0)
  const [wheelToApplication, setWheelToApplication] = useState(0)

  /** The grid the surface holds at the current cell size, as the renderer measures its cells. */
  const measure = useCallback((): TerminalGrid => {
    const proposed = renderer.current?.fit.proposeDimensions()
    if (
      proposed !== undefined &&
      Number.isFinite(proposed.cols) &&
      Number.isFinite(proposed.rows) &&
      proposed.cols > 0 &&
      proposed.rows > 0
    ) {
      return { columns: proposed.cols, rows: proposed.rows }
    }
    return FALLBACK_GRID
  }, [])

  // The renderer is created again for each session, so nothing written for one session can reach
  // another's screen, and for each cell size, because it measures its cell once.
  useEffect(() => {
    const element = host.current
    if (!element) return
    const created = new Terminal({
      fontFamily: 'ui-monospace, SFMono-Regular, Consolas, monospace',
      fontSize: BASE_FONT_SIZE * (ZOOM_STEPS[zoom] ?? 1),
      convertEol: false,
      cursorBlink: false,
      // The host owns scrollback. A buffer here would be a second, disagreeing copy of it.
      scrollback: 0,
      allowProposedApi: true
    })
    const fit = new FitAddon()
    created.loadAddon(fit)
    created.open(element)
    renderer.current = { terminal: created, fit }
    setGeneration((count) => count + 1)
    return () => {
      created.dispose()
      if (renderer.current?.terminal === created) renderer.current = null
    }
  }, [zoom, sessionId])

  const { state, frame, slow, resize, again } = useTerminalView(port, sessionId, measure)

  // The last complete screen, drawn in one write, in the palette the session has.
  useEffect(() => {
    const current = renderer.current
    if (!current) return
    if (frame !== null) current.terminal.options.theme = themeOf(frame.palette)
    paint(current.terminal, frame)
  }, [frame, generation])

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
  }, [generation, resize, measure])

  // The wheel is read here rather than through a React handler, because the renderer inside this
  // element listens for it too. In control mode it must reach the program unchanged, so this
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
  const truncated = frame?.lines.some((line) => line.truncated) ?? false

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
            {frame.replaced > 0 ? (
              <Badge tone="warning" data-testid="substituted-count">
                {frame.replaced} left blank
              </Badge>
            ) : null}
            {truncated ? (
              <Badge tone="warning" data-testid="rows-truncated">
                Rows cut short
              </Badge>
            ) : null}
            {frame.degraded ? (
              <Badge tone="warning" data-testid="screen-degraded">
                Shortened by the session
              </Badge>
            ) : null}
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
        <div ref={host} style={{ position: 'absolute', inset: SURFACE_INSET }} />
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
