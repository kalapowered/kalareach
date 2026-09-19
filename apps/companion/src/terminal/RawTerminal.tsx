/**
 * The raw terminal view.
 *
 * It draws the host's projection through xterm.js. The projection is already a grid of resolved
 * cells, so this does not run a terminal state machine of its own: it writes the rows it was given
 * at the positions they name, substituting any cluster this renderer cannot draw for exactly as
 * many columns as that cluster declared.
 *
 * Two modes, and the wheel belongs to whichever one is active. In control mode the application
 * inside the terminal gets the wheel, unchanged. In view mode the person is looking around the
 * projection and the view pans and zooms. Switching to the rich view releases this view's own
 * geometry claim and nothing else.
 */

import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react'
import { Terminal } from '@xterm/xterm'
import '@xterm/xterm/css/xterm.css'

import { Badge, Button, Segmented } from '../components/ui'
import { ENVIRONMENT_ID, useApp } from '../app/state'
import { failureMessage, type ProjectedScreen } from '../host/port'
import { drawRow, measuredReproducible } from './clusters'
import {
  describeProvenance,
  routeWheel,
  zoomBy,
  ZOOM_DEFAULT_INDEX,
  ZOOM_STEPS,
  type ViewMode
} from './modes'

/** The base cell size before zoom. */
const BASE_FONT_SIZE = 12

/** The raw view of one session. */
export function RawTerminal({
  sessionId,
  attachmentId,
  onReleaseGeometry
}: {
  readonly sessionId: string
  readonly attachmentId: string
  readonly onReleaseGeometry: () => void
}): ReactNode {
  const { port, say } = useApp()
  const host = useRef<HTMLDivElement | null>(null)
  const terminal = useRef<Terminal | null>(null)
  const [mode, setMode] = useState<ViewMode>('control')
  const [zoom, setZoom] = useState(ZOOM_DEFAULT_INDEX)
  const [screen, setScreen] = useState<ProjectedScreen | null>(null)
  const [substituted, setSubstituted] = useState(0)
  const [failure, setFailure] = useState<string | null>(null)
  const [wheelToApplication, setWheelToApplication] = useState(0)

  useEffect(() => {
    const element = host.current
    if (!element) return
    const created = new Terminal({
      fontFamily: 'ui-monospace, SFMono-Regular, Consolas, monospace',
      fontSize: BASE_FONT_SIZE * (ZOOM_STEPS[zoom] ?? 1),
      convertEol: false,
      // The host owns scrollback. A buffer here would be a second, disagreeing copy of it.
      scrollback: 0,
      allowProposedApi: true
    })
    created.open(element)
    terminal.current = created
    return () => {
      created.dispose()
      terminal.current = null
    }
    // The terminal is recreated when the cell size changes, because xterm measures its cell once.
  }, [zoom])

  const load = useCallback(() => {
    port
      .terminalProjection(ENVIRONMENT_ID, { session_id: sessionId })
      .then((projection) => {
        setScreen(projection)
        setFailure(null)
      })
      .catch((error: unknown) => {
        setFailure(failureMessage(error))
      })
  }, [port, sessionId])

  useEffect(load, [load])

  useEffect(() => {
    const created = terminal.current
    if (!created || !screen) return

    // What this renderer can actually draw, measured rather than assumed.
    const canvas = document.createElement('canvas')
    const context = canvas.getContext('2d')
    const font = `${BASE_FONT_SIZE * (ZOOM_STEPS[zoom] ?? 1)}px ui-monospace, monospace`
    if (context) context.font = font
    const cellWidth = context?.measureText('M').width ?? BASE_FONT_SIZE * 0.6
    const reproducible = measuredReproducible(
      (text) => context?.measureText(text).width ?? 0,
      cellWidth
    )

    created.reset()
    let replaced = 0
    for (const row of screen.rows) {
      const drawn = drawRow(row.cells, reproducible)
      replaced += drawn.substituted
      created.write(`${drawn.text}\r\n`)
    }
    setSubstituted(replaced)
  }, [screen, zoom])

  const columns = Number(screen?.dimensions.columns ?? '0')
  const rows = Number(screen?.dimensions.rows ?? '0')

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
              : 'Pan and zoom the projection. The program gets nothing.'}
          </span>
        </span>
        <span className="row">
          <Badge tone="neutral" data-testid="palette-provenance">
            Palette: {describeProvenance(screen?.palette_provenance ?? 'unknown')}
          </Badge>
          <Badge tone="neutral">
            {columns}×{rows}
          </Badge>
          {substituted > 0 ? (
            <Badge tone="warning" data-testid="substituted-count">
              {substituted} {substituted === 1 ? 'cell' : 'cells'} replaced
            </Badge>
          ) : null}
        </span>
      </header>

      {failure ? (
        <p className="banner warning" role="status">
          {failure}
        </p>
      ) : null}

      <div
        className="terminal-surface"
        ref={host}
        data-testid="terminal-surface"
        data-wheel-to-application={wheelToApplication}
        onWheel={(event) => {
          const outcome = routeWheel(mode, {
            deltaX: event.deltaX,
            deltaY: event.deltaY,
            zoomGesture: event.ctrlKey
          })
          if (outcome.kind === 'application') {
            // The application's own scroll. The view neither consumes nor cancels it: it goes to
            // the program as the wheel event it is.
            setWheelToApplication((count) => count + 1)
            void port
              .terminalInput(ENVIRONMENT_ID, {
                session_id: sessionId,
                wheel: { lines: outcome.lines }
              })
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
          void port
            .attachmentViewport(ENVIRONMENT_ID, {
              attachment_id: attachmentId,
              session_id: sessionId,
              viewport: { rows_above: outcome.rows, columns: outcome.columns }
            })
            .then(load)
            .catch(() => {
              // Nothing to say: the projection stays where it was.
            })
        }}
      />

      <footer className="terminal-footer between">
        <span className="small faint">
          {screen?.viewport_top_row === null
            ? 'At the live end.'
            : `Showing history from row ${screen?.viewport_top_row ?? 0}. Oldest retained row is ${screen?.oldest_retained_row ?? 0}.`}
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
          <Button
            data-testid="release-geometry"
            onClick={() => {
              onReleaseGeometry()
              say('This view released its size claim.')
            }}
          >
            Back to the conversation
          </Button>
        </span>
      </footer>
    </section>
  )
}
