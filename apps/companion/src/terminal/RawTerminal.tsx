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

import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { Terminal } from '@xterm/xterm'
import '@xterm/xterm/css/xterm.css'

import { Badge, Button, Segmented } from '../components/ui'
import { useApp } from '../app/state'
import {
  failureMessage,
  watch,
  type ProjectedScreen,
  type SessionSubject,
  type Watch
} from '../host/port'
import { ask } from '../mobile/model/call'
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
  subject,
  attachmentId,
  onReleaseGeometry
}: {
  readonly sessionId: string
  readonly subject: SessionSubject
  readonly attachmentId: string
  readonly onReleaseGeometry: () => void
}): ReactNode {
  const { port, say } = useApp()
  const host = useRef<HTMLDivElement | null>(null)
  const terminal = useRef<Terminal | null>(null)
  const [mode, setMode] = useState<ViewMode>('control')
  const [zoom, setZoom] = useState(ZOOM_DEFAULT_INDEX)
  // The screen and the failure the newest read answered, each with the session it was read for.
  const [shown, setShown] = useState<{ readonly sessionId: string; readonly screen: ProjectedScreen } | null>(
    null
  )
  const [failed, setFailed] = useState<{ readonly sessionId: string; readonly message: string } | null>(
    null
  )
  const [wheelToApplication, setWheelToApplication] = useState(0)
  // Every read of the screen, on opening and after the window moves, is made under one watch with
  // no listeners, which starts again for each session: only the newest read's answer is shown, and
  // nothing read for a session the view has left.
  const reads = useRef<Watch | null>(null)
  const screen = shown?.sessionId === sessionId ? shown.screen : null
  const failure = failed?.sessionId === sessionId ? failed.message : null

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
    const current = reads.current?.read() ?? null
    if (current === null) return
    ask(() => port.terminalProjection({ session_id: sessionId }))
      .then((projection) => {
        if (!current()) return
        setShown({ sessionId, screen: projection })
        setFailed(null)
      })
      .catch((error: unknown) => {
        if (!current()) return
        setFailed({ sessionId, message: failureMessage(error) })
      })
  }, [port, sessionId])

  useEffect(() => {
    const reading = watch([], load)
    reads.current = reading
    return () => {
      reading.stop()
      if (reads.current === reading) reads.current = null
    }
  }, [load])

  // This session's screen as this renderer draws it at this cell size, or nothing before it has
  // been read.
  const drawing = useMemo(() => (screen ? drawScreen(screen, zoom) : null), [screen, zoom])
  const substituted = drawing?.substituted ?? 0

  useEffect(() => {
    const created = terminal.current
    if (!created) return
    // Nothing is drawn but this session's screen: until it has been read, the terminal is empty.
    created.reset()
    if (!drawing) return
    for (const line of drawing.lines) created.write(`${line}\r\n`)
  }, [drawing])

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
        return
      }
      void port
        .attachmentViewport(
          {
            attachment_id: attachmentId,
            session_id: sessionId,
            viewport: { rows_above: outcome.rows, columns: outcome.columns }
          },
          subject
        )
        .then(load)
        .catch(() => {
          // Nothing to say: the projection stays where it was.
        })
    }
    element.addEventListener('wheel', onWheel, { capture: true, passive: false })
    return () => {
      element.removeEventListener('wheel', onWheel, { capture: true })
    }
  }, [mode, port, sessionId, attachmentId, subject, load])

  const columns = Number(screen?.dimensions.columns ?? '0')
  const rows = Number(screen?.dimensions.rows ?? '0')
  // What the screen says about itself is shown once a screen has been read, and not before: a size,
  // a palette or a window claimed ahead of the answer would be the view's guess.
  const position =
    screen === null
      ? null
      : screen.viewport_top_row === null
        ? 'At the live end.'
        : `Showing history from row ${screen.viewport_top_row}. Oldest retained row is ${screen.oldest_retained_row}.`

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
        {screen ? (
          <span className="row">
            <Badge tone="neutral" data-testid="palette-provenance">
              Palette: {describeProvenance(screen.palette_provenance)}
            </Badge>
            <Badge tone="neutral" data-testid="terminal-size">
              {`${columns}×${rows}`}
            </Badge>
            {substituted > 0 ? (
              <Badge tone="warning" data-testid="substituted-count">
                {substituted} {substituted === 1 ? 'cell' : 'cells'} replaced
              </Badge>
            ) : null}
          </span>
        ) : null}
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
      />

      <footer className="terminal-footer between">
        <span className="small faint" data-testid="terminal-position">
          {position}
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

/**
 * One screen as this renderer draws it: each row as text, and how many cells it had to replace.
 *
 * What the renderer can draw is measured at the cell size in use rather than assumed, so a cluster
 * it cannot reproduce is replaced by exactly as many columns as the cluster declared.
 */
function drawScreen(
  screen: ProjectedScreen,
  zoom: number
): { readonly lines: readonly string[]; readonly substituted: number } {
  const canvas = document.createElement('canvas')
  const context = canvas.getContext('2d')
  const font = `${BASE_FONT_SIZE * (ZOOM_STEPS[zoom] ?? 1)}px ui-monospace, monospace`
  if (context) context.font = font
  const cellWidth = context?.measureText('M').width ?? BASE_FONT_SIZE * 0.6
  const reproducible = measuredReproducible(
    (text) => context?.measureText(text).width ?? 0,
    cellWidth
  )
  let substituted = 0
  const lines = screen.rows.map((row) => {
    const drawn = drawRow(row.cells, reproducible)
    substituted += drawn.substituted
    return drawn.text
  })
  return { lines, substituted }
}
