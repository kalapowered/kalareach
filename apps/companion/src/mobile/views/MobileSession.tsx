/**
 * One session on a phone: the conversation, the raw terminal, and the composer under both.
 *
 * The two views share the draft and the scroll position, so switching between them is switching
 * the view and not starting again. The composer gives local feedback the instant the person sends
 * something and waits for a receipt before it says anything was applied, because a request that
 * reached the host is not a prompt the agent took.
 *
 * The terminal view is the one with a rule in it. In control mode the program inside the terminal
 * owns the touch, exactly as it owns the wheel on a desktop, and the view's own pan does not
 * exist. Only a pinch zooms, because nothing on the wire carries a pinch, so zooming takes nothing
 * from anyone.
 */

import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react'

import { useApp } from '../../app/state'
import { Badge, Banner, Button, Segmented } from '../../components/ui'
import { failureMessage } from '../../host/port'
import {
  edit,
  notSubmittableBecause,
  startDraft,
  submittable,
  type Draft
} from '../../model/drafts'
import {
  describeState,
  queued,
  reconnectBanner,
  sent,
  settled,
  failed
} from '../../model/receipts'
import { renderMarkdown } from '../../markdown/render'
import { ZOOM_DEFAULT_INDEX, ZOOM_STEPS, zoomBy, type ViewMode } from '../../terminal/modes'
import { AccessoryRow } from '../components/keys'
import { AttachmentPicker } from '../components/picker'
import { sequenceForKeyPress, afterKey, pressModifier, sequenceFor, NO_LATCH, type Latch } from '../model/accessory'
import { describeMode, routeGesture, type TouchGesture } from '../model/gestures'
import { admit, describeBytes } from '../model/media'
import type { Lifecycle } from '../useLifecycle'
import { minimumTarget, type Surface } from '../platform'

/** Which of the two views is showing. */
type Pane = 'semantic' | 'terminal'

/** One node as the phone holds it. */
interface ReadNode {
  readonly id: string
  readonly role: string
  readonly text: string
  /** True when the text is Markdown the allowlisted renderer draws. */
  readonly markdown?: boolean
}

/** No image has been imported: a renderer never fetches one on a person's behalf. */
const NO_IMAGES: ReadonlyMap<string, string> = new Map()

/** The session screen. */
export function MobileSession({
  sessionId,
  surface,
  lifecycle,
  connected
}: {
  readonly sessionId: string
  readonly surface: Surface
  readonly lifecycle: Lifecycle
  readonly connected: boolean
}): ReactNode {
  const { port, say } = useApp()
  const [pane, setPane] = useState<Pane>('semantic')
  const [nodes, setNodes] = useState<readonly ReadNode[]>([])
  const [screen, setScreen] = useState<readonly string[]>([])
  const [mode, setMode] = useState<ViewMode>('control')
  const [zoom, setZoom] = useState(ZOOM_DEFAULT_INDEX)
  const [pan, setPan] = useState({ x: 0, y: 0 })
  const [latch, setLatch] = useState<Latch>(NO_LATCH)
  const [busy, setBusy] = useState(false)
  const target = minimumTarget(surface)
  // One scroll position per view, kept across a switch: coming back to a view you were reading
  // halfway down and finding the top of it is losing your place.
  const positions = useRef<Record<Pane, number>>({ semantic: 0, terminal: 0 })
  const paneRef = useRef<HTMLDivElement | null>(null)

  // The clock is read once, when this screen opens. Reading it while rendering would make the
  // empty draft a different object on every render and the composer would lose what was typed.
  const [openedAtMs] = useState(() => Date.now())
  const held = lifecycle.state.drafts.find((each) => each.target.sessionId === sessionId)
  const draft = useMemo(
    () =>
      held ??
      startDraft(
        `draft-${sessionId}`,
        { sessionId, applicationInstanceId: null, agentBindingRevision: null },
        openedAtMs
      ),
    [held, sessionId, openedAtMs]
  )

  const setDraft = useCallback(
    (next: Draft) => {
      lifecycle.setDrafts((drafts) => {
        const without = drafts.filter((each) => each.draftId !== next.draftId)
        return [...without, next]
      })
    },
    [lifecycle]
  )

  useEffect(() => {
    port
      .agentSnapshot({ session_id: sessionId })
      .then((answer) => {
        setNodes(answer.nodes.slice(-80).map(readNode))
      })
      .catch(() => {
        setNodes([])
      })
  }, [port, sessionId])

  useEffect(() => {
    if (pane !== 'terminal') return
    port
      .terminalProjection({ session_id: sessionId })
      .then((projection) => {
        setScreen(
          projection.rows.map((row) => row.cells.map((cell) => cell.text || ' ').join(''))
        )
      })
      .catch(() => {
        setScreen([])
      })
  }, [port, sessionId, pane])

  // Restoring the position happens after the view has drawn, which is the only moment the element
  // is tall enough to be scrolled to where it was.
  useEffect(() => {
    const element = paneRef.current
    if (!element) return
    element.scrollTop = positions.current[pane]
  }, [pane])

  const remember = () => {
    const element = paneRef.current
    if (element) positions.current[pane] = element.scrollTop
  }

  const send = useCallback(
    (text: string) => {
      const now = Date.now()
      const submission = queued(`local-${now}`, text.slice(0, 60), now, text)
      // Local feedback first, and it says queued rather than sent, because it has not left yet.
      lifecycle.setSubmissions((current) => [...current, submission])
      setBusy(true)
      port
        .composerSubmit({ session_id: sessionId, text }, { sessionId })
        .then((answer) => {
          lifecycle.setSubmissions((current) =>
            current.map((each) => {
              if (each.localId !== submission.localId) return each
              const withAction = answer.action_id ? sent(each, answer.action_id) : each
              // Only a receipt makes it applied. Without one it stays with the host and says so.
              return answer.receipt ? settled(withAction, answer.receipt) : withAction
            })
          )
          setDraft(edit(draft, '', Date.now()))
        })
        .catch((failure: unknown) => {
          lifecycle.setSubmissions((current) =>
            current.map((each) =>
              each.localId === submission.localId
                ? failed(each, { code: 'REQUEST_FAILED', message: failureMessage(failure) })
                : each
            )
          )
          // The text comes back. A refusal must never be a way to lose what someone wrote.
          say(failureMessage(failure), 'danger')
        })
        .finally(() => {
          setBusy(false)
        })
    },
    [draft, lifecycle, port, say, sessionId, setDraft]
  )

  const sendKeys = useCallback(
    (bytes: string) => {
      port.terminalInput({ session_id: sessionId, bytes }).catch((failure: unknown) => {
        say(failureMessage(failure), 'danger')
      })
    },
    [port, say, sessionId]
  )

  const banner = reconnectBanner(connected, lifecycle.state.submissions)
  const blocked = notSubmittableBecause(draft)

  return (
    <div className="m-session">
      <div>
        {lifecycle.banner ? (
          <Banner
            tone={lifecycle.banner.tone}
            title={lifecycle.banner.title}
            detail={lifecycle.banner.detail}
            action={
              <Button onClick={lifecycle.acknowledge}>Dismiss</Button>
            }
          />
        ) : null}
        {banner ? <Banner tone={banner.tone} title={banner.title} detail={banner.detail} /> : null}
        <Segmented
          label="Session view"
          value={pane}
          onChange={(next) => {
            remember()
            setPane(next)
          }}
          options={[
            { value: 'semantic', label: 'Conversation' },
            { value: 'terminal', label: 'Terminal' }
          ]}
        />
      </div>

      <div className="m-pane" ref={paneRef} onScroll={remember}>
        {pane === 'semantic' ? (
          <div className="m-stream" data-testid="mobile-conversation">
            {nodes.length === 0 ? (
              <p className="m-empty">Nothing in this conversation yet.</p>
            ) : (
              nodes.map((node) => (
                <div key={node.id} className="m-node">
                  <p className="m-node-role">{node.role}</p>
                  {node.markdown ? (
                    // The same allowlisted renderer the desktop window uses: an element tree from
                    // a parser's tokens, never a string of markup.
                    <div>
                      {renderMarkdown(node.text, {
                        openLink: (url) => {
                          port.openExternal(url).catch((failure: unknown) => {
                            say(failureMessage(failure), 'danger')
                          })
                        },
                        importImage: () => undefined,
                        importedImages: NO_IMAGES
                      })}
                    </div>
                  ) : (
                    <p>{node.text}</p>
                  )}
                </div>
              ))
            )}
          </div>
        ) : (
          <RawTerminal
            rows={screen}
            mode={mode}
            zoom={zoom}
            pan={pan}
            onPan={setPan}
            onZoom={(steps) => {
              setZoom((index) => zoomBy(index, steps))
            }}
            onApplicationScroll={(lines) => {
              sendKeys(lines > 0 ? '\u001b[A'.repeat(Math.min(10, lines)) : '\u001b[B'.repeat(Math.min(10, -lines)))
            }}
          />
        )}
      </div>

      <div className="m-composer">
        {pane === 'terminal' ? (
          <>
            <div className="m-terminal-hud">
              <Badge tone={mode === 'control' ? 'accent' : 'neutral'}>{mode === 'control' ? 'Control' : 'View'}</Badge>
              <span>{describeMode(mode)}</span>
              <Button
                onClick={() => {
                  setMode((current) => (current === 'control' ? 'view' : 'control'))
                }}
              >
                {mode === 'control' ? 'Look around' : 'Take control'}
              </Button>
              <span>{`Zoom ${Math.round((ZOOM_STEPS[zoom] ?? 1) * 100)}%`}</span>
            </div>
            <AccessoryRow
              surface={surface}
              latch={latch}
              onKey={(key) => {
                if (key.modifier) {
                  setLatch((current) => pressModifier(current, key.modifier as 'ctrl' | 'alt' | 'shift'))
                  return
                }
                const bytes = sequenceFor(key, latch)
                setLatch((current) => afterKey(current))
                if (bytes !== null) sendKeys(bytes)
              }}
            />
          </>
        ) : null}

        {draft.attachments.length > 0 ? (
          <div className="m-attachments">
            {draft.attachments.map((attachment) => (
              <span key={attachment.transferId} className="m-attachment">
                {attachment.name}
                <span className="m-row-detail">{describeBytes(attachment.byteLen)}</span>
              </span>
            ))}
          </div>
        ) : null}

        <label className="visually-hidden" htmlFor={`composer-${sessionId}`}>
          Message this session
        </label>
        <textarea
          id={`composer-${sessionId}`}
          value={draft.text}
          placeholder={pane === 'terminal' ? 'Type into the terminal' : 'Message this session'}
          aria-describedby={blocked ? `composer-why-${sessionId}` : undefined}
          onChange={(event) => {
            setDraft(edit(draft, event.target.value, Date.now()))
          }}
          onKeyDown={(event) => {
            if (pane !== 'terminal') return
            const bytes = sequenceForKeyPress(event)
            if (bytes === null) return
            // A hardware keyboard drives the terminal directly; the field is only where the
            // person is looking.
            if (event.key.length === 1 && !event.ctrlKey && !event.altKey) return
            event.preventDefault()
            sendKeys(bytes)
          }}
        />
        {blocked ? (
          <p className="m-hint" id={`composer-why-${sessionId}`}>
            {blocked}
          </p>
        ) : null}

        <AttachmentPicker
          surface={surface}
          onPicked={(files) => {
            for (const { picked } of files) {
              const admission = admit(picked)
              if (!admission.admitted) {
                say(admission.reason, 'danger')
                continue
              }
              say(`${picked.name} is ready to send.`, 'success')
            }
          }}
        />

        <div className="m-composer-actions">
          <Button
            tone="primary"
            disabled={!submittable(draft) || busy}
            style={{ minBlockSize: target }}
            onClick={() => {
              send(draft.text)
            }}
          >
            Send
          </Button>
          {lifecycle.state.submissions.slice(-1).map((submission) => (
            <Badge
              key={submission.localId}
              tone={submission.state === 'applied' ? 'success' : submission.state === 'queued' ? 'neutral' : 'accent'}
            >
              {describeState(submission.state)}
            </Badge>
          ))}
        </div>
      </div>
    </div>
  )
}

/** The projection, with the view's own pan and zoom over it. */
function RawTerminal({
  rows,
  mode,
  zoom,
  pan,
  onPan,
  onZoom,
  onApplicationScroll
}: {
  readonly rows: readonly string[]
  readonly mode: ViewMode
  readonly zoom: number
  readonly pan: { readonly x: number; readonly y: number }
  readonly onPan: (pan: { x: number; y: number }) => void
  readonly onZoom: (steps: number) => void
  readonly onApplicationScroll: (lines: number) => void
}): ReactNode {
  const pointers = useRef(new Map<number, { x: number; y: number }>())
  const start = useRef<{ x: number; y: number; spread: number } | null>(null)

  const gestureFrom = (event: React.PointerEvent): TouchGesture => {
    const origin = start.current
    const points = [...pointers.current.values()]
    const spread =
      points.length >= 2 && points[0] && points[1]
        ? Math.hypot(points[0].x - points[1].x, points[0].y - points[1].y)
        : 0
    return {
      pointers: pointers.current.size,
      deltaX: origin ? event.clientX - origin.x : 0,
      deltaY: origin ? event.clientY - origin.y : 0,
      scale: origin && origin.spread > 0 && spread > 0 ? spread / origin.spread : 1
    }
  }

  return (
    <div
      className="m-terminal"
      data-mode={mode}
      data-testid="mobile-terminal"
      style={
        {
          '--zoom': ZOOM_STEPS[zoom] ?? 1,
          '--pan-x': pan.x,
          '--pan-y': pan.y
        } as React.CSSProperties
      }
      onPointerDown={(event) => {
        event.currentTarget.setPointerCapture(event.pointerId)
        pointers.current.set(event.pointerId, { x: event.clientX, y: event.clientY })
        const points = [...pointers.current.values()]
        start.current = {
          x: event.clientX,
          y: event.clientY,
          spread:
            points.length >= 2 && points[0] && points[1]
              ? Math.hypot(points[0].x - points[1].x, points[0].y - points[1].y)
              : 0
        }
      }}
      onPointerMove={(event) => {
        if (!pointers.current.has(event.pointerId)) return
        pointers.current.set(event.pointerId, { x: event.clientX, y: event.clientY })
        const outcome = routeGesture(mode, gestureFrom(event))
        if (outcome.kind === 'pan') {
          onPan({ x: pan.x - outcome.columns, y: pan.y - outcome.rows })
        }
      }}
      onPointerUp={(event) => {
        const gesture = gestureFrom(event)
        const outcome = routeGesture(mode, gesture)
        pointers.current.delete(event.pointerId)
        start.current = null
        if (outcome.kind === 'zoom') onZoom(outcome.steps)
        // In control mode the movement was the program's, so it is handed over rather than used.
        if (outcome.kind === 'application' && outcome.lines !== 0) onApplicationScroll(outcome.lines)
      }}
      onPointerCancel={(event) => {
        pointers.current.delete(event.pointerId)
        start.current = null
      }}
    >
      <pre className="m-terminal-grid">{rows.join('\n')}</pre>
    </div>
  )
}

/**
 * One document node, as the phone shows it.
 *
 * A phone shows less than a desktop window does, and what it shows is the node's own words rather
 * than a rendering of every kind it could be. Each kind names itself, so a node this build does
 * not draw fully is still a node the person can see is there.
 */
function readNode(node: unknown, index: number): ReadNode {
  const outer = node as { id?: string; body?: Record<string, unknown> }
  const body = outer.body ?? {}
  // Only a string is text. A field that is not one is a node shape this build does not draw, and
  // showing "[object Object]" to a person would be worse than showing the kind alone.
  const text = (name: string): string => (typeof body[name] === 'string' ? body[name] : '')
  const kind = text('kind') || 'node'
  const id = outer.id ?? String(index)
  switch (kind) {
    case 'message':
      return { id, role: text('author') || 'message', text: text('text') }
    case 'markdown':
      return { id, role: 'assistant', text: text('source'), markdown: true }
    case 'tool': {
      const summary = text('summary')
      return {
        id,
        role: `tool · ${text('name')}`,
        text: summary ? `${text('outcome')} · ${summary}` : text('outcome')
      }
    }
    case 'diff': {
      const files = (body['files'] as { path?: string; added?: number; removed?: number }[]) ?? []
      return {
        id,
        role: 'change',
        text: files
          .map((file) => `${file.path ?? ''} +${file.added ?? 0} −${file.removed ?? 0}`)
          .join(', ')
      }
    }
    case 'approval_ref':
      return { id, role: 'decision', text: 'A decision is waiting in the inbox.' }
    case 'action_group':
      return { id, role: 'actions', text: text('label') }
    default:
      return { id, role: kind, text: '' }
  }
}
