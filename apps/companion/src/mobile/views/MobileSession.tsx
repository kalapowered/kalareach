/**
 * One session on a phone: the conversation, the raw terminal, and the composer under both.
 *
 * The two views share the draft and the scroll position, so switching between them is switching
 * the view and not starting again. The composer gives local feedback the instant the person sends
 * something and waits for a receipt before it says anything was applied, because a request that
 * reached the host is not a prompt the agent took.
 *
 * The terminal view is the one with a rule in it. In control mode the program inside the terminal
 * owns the touch, exactly as it owns the wheel on a desktop. Only a pinch zooms, because nothing on
 * the wire carries a pinch, so zooming takes nothing from anyone. In view mode a one-finger drag
 * moves the window across the session, up into its history and down its live screen: the screen
 * follows the finger, and comes to rest on the screen the host draws for the window's new place.
 * Taking control brings a window in the history back to the live screen. A finger that is down
 * when the view changes under it, another opening, mode or life, counts for nothing until it lifts.
 * In view mode a press is the view's alone: whatever the page has selected, the browser starts no
 * selection and no native drag of its own, so a drag always moves the window. Control mode leaves
 * the browser its own way with the text.
 */

import { useCallback, useEffect, useId, useLayoutEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { flushSync } from 'react-dom'

import { useApp } from '../../app/state'
import { Badge, Banner, Button, Segmented } from '../../components/ui'
import { failureCode, failureMessage, watch, type Watch } from '../../host/port'
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
  stateOfReceipt,
  unresolved,
  wasRefused,
  failed
} from '../../model/receipts'
import { renderMarkdown } from '../../markdown/render'
import type { TerminalGrid, TerminalRoom, TerminalScreen } from '../../host/port'
import { leftBlankOnPhone, stretchesOf, styleOf } from '../../terminal/cells'
import { selectionRule } from '../../terminal/frame'
import {
  ATTACHING,
  placeOf,
  presentationOf,
  WAITING,
  warningsOf,
  ZOOM_DEFAULT_INDEX,
  ZOOM_STEPS,
  zoomBy,
  type ViewMode
} from '../../terminal/modes'
import {
  beginDrag,
  dragTo,
  releaseDrag,
  restartDrag,
  type Cells,
  type CellSize,
  type HeldDrag,
  type Point
} from '../../terminal/pan'
import { FALLBACK_GRID, useTerminalView } from '../../terminal/view'
import { AccessoryRow } from '../components/keys'
import { AttachmentPicker } from '../components/picker'
import { sequenceForKeyPress, afterKey, pressModifier, sequenceFor, NO_LATCH, type Latch } from '../model/accessory'
import { ask } from '../model/call'
import { describeMode, routeGesture, type TouchGesture } from '../model/gestures'
import { admit, describeBytes, type Picked } from '../model/media'
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

/**
 * This device's identity for one submission.
 *
 * The session is in it because the submissions are held for the whole device: an outcome from one
 * session shown under another is a person told their message was applied when it was somebody
 * else's that was.
 */
function localId(sessionId: string, now: number): string {
  return `local:${sessionId}:${now}`
}

/** Whether a submission belongs to one session. */
function isForSession(id: string, sessionId: string): boolean {
  return id.startsWith(`local:${sessionId}:`)
}

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
  /** Whether the host is in contact, or null before the shell's first answer. */
  readonly connected: boolean | null
}): ReactNode {
  const { port, say } = useApp()
  const [pane, setPane] = useState<Pane>('semantic')
  // What each read answered, kept with the session it was read for and shown only for that
  // session: from the first render after a change of session, nothing of the last one is shown.
  // The conversation is a refusal's words, or the nodes read, or nothing before the first answer.
  const [conversation, setConversation] = useState<{
    readonly sessionId: string
    readonly nodes: readonly ReadNode[]
    readonly refusal: string | null
  } | null>(null)
  const read = conversation?.sessionId === sessionId ? conversation : null
  const nodes = read?.nodes ?? []
  const [mode, setMode] = useState<ViewMode>('control')
  const [zoom, setZoom] = useState(ZOOM_DEFAULT_INDEX)
  const [latch, setLatch] = useState<Latch>(NO_LATCH)
  const [busy, setBusy] = useState(false)
  // Whether the terminal's status shows all it says, rather than its first two lines.
  const [statusOpen, setStatusOpen] = useState(false)
  const statusId = useId()
  // What the person picked, held here until there is a command that carries bytes to a host. It
  // is shown rather than dropped, because a file that vanishes after a success message is worse
  // than one that says plainly it has not gone anywhere.
  const [heldFiles, setHeldFiles] = useState<
    readonly { readonly picked: Picked; readonly file: File }[]
  >([])
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

  // The conversation is read under a watch with no listeners that ends with the session: only the
  // newest read's answer is shown, and what an ended watch read goes with it.
  useEffect(() => {
    const reading: Watch = watch([], () => {
      const current = reading.read()
      if (current === null) return
      ask(() => port.agentSnapshot({ session_id: sessionId }))
        .then((answer) => {
          if (!current()) return
          setConversation({ sessionId, nodes: answer.nodes.slice(-80).map(readNode), refusal: null })
        })
        .catch((failure: unknown) => {
          if (!current()) return
          setConversation({ sessionId, nodes: [], refusal: failureMessage(failure) })
        })
    })
    return () => {
      reading.stop()
      setConversation(null)
    }
  }, [port, sessionId])

  // The terminal's grid: as many cells as its surface shows at the current zoom, a column measured
  // from a probe of the grid's own font and a row as tall as the grid's own lines.
  const terminalSurface = useRef<HTMLDivElement | null>(null)
  const cellProbe = useRef<HTMLSpanElement | null>(null)
  const measure = useCallback((): TerminalGrid => {
    const surfaceElement = terminalSurface.current
    const grid = cellProbe.current?.parentElement
    const cell = cellOf(cellProbe.current)
    if (!surfaceElement || !grid || cell === null) return FALLBACK_GRID
    const style = getComputedStyle(grid)
    const across =
      surfaceElement.clientWidth - parseFloat(style.paddingLeft) - parseFloat(style.paddingRight)
    const down =
      surfaceElement.clientHeight - parseFloat(style.paddingTop) - parseFloat(style.paddingBottom)
    const columns = Math.floor(across / cell.width)
    const rows = Math.floor(down / cell.height)
    return Number.isFinite(columns) && Number.isFinite(rows) && columns > 0 && rows > 0
      ? { columns, rows }
      : FALLBACK_GRID
  }, [])

  // The terminal's view is open while the terminal is shown, and closed when the person goes back
  // to the conversation or the session changes.
  const {
    state: terminal,
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
    live
  } = useTerminalView(port, sessionId, measure, pane === 'terminal')
  const terminalAttachmentSummary =
    terminal !== null && terminal.state !== 'ended' ? terminal.attachment : null
  const presented =
    terminalAttachmentSummary === null ? null : presentationOf(terminalAttachmentSummary)
  const terminalWaiting = terminal?.state === 'waiting'
  const terminalPosition =
    (terminalWaiting && (frame === null || slow)) || movingSlow
      ? WAITING
      : frame === null
        ? null
        : placeOf(frame)

  // The grid goes to the host when the terminal is shown, when the zoom changes, and as its surface
  // is resized: by the screen, the keyboard, or the composer beneath it.
  useEffect(() => {
    if (pane !== 'terminal') return
    resize(measure())
    const element = terminalSurface.current
    if (!element || typeof ResizeObserver === 'undefined') return
    const observer = new ResizeObserver(() => {
      resize(measure())
    })
    observer.observe(element)
    return () => {
      observer.disconnect()
    }
  }, [pane, zoom, resize, measure])

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
      // The session is in the identity, so one session's outcome is never shown under another.
      const submission = queued(localId(sessionId, now), text.slice(0, 60), now, text)
      // The revision the person submitted. Anything typed after it is a newer draft, and a late
      // answer about the older one must not take it away.
      const submittedRevision = draft.revision
      // Local feedback first, and it says queued rather than sent, because it has not left yet.
      lifecycle.setSubmissions((current) => [...current, submission])
      setBusy(true)
      ask(() => port.composerSubmit({ session_id: sessionId, text }, { sessionId }))
        .then((answer) => {
          const state = answer.receipt ? stateOfReceipt(answer.receipt) : 'sent'
          lifecycle.setSubmissions((current) =>
            current.map((each) => {
              if (each.localId !== submission.localId) return each
              const withAction = answer.action_id ? sent(each, answer.action_id) : each
              // Only a receipt makes it applied. Without one it stays with the host and says so.
              return answer.receipt ? settled(withAction, answer.receipt) : withAction
            })
          )
          if (wasRefused(state)) {
            // The submission did not happen. The text stays exactly where it was.
            say(`The host refused it. What you wrote is still here.`, 'danger')
            return
          }
          // The composer is cleared only when it still holds what was submitted. A person who
          // typed the next thing while this one was in flight keeps what they typed.
          lifecycle.setDrafts((drafts) =>
            drafts.map((each) =>
              each.draftId === draft.draftId && each.revision === submittedRevision
                ? edit(each, '', Date.now())
                : each
            )
          )
        })
        .catch((failure: unknown) => {
          lifecycle.setSubmissions((current) =>
            current.map((each) =>
              each.localId === submission.localId
                ? // The host's own code, kept: `OUTCOME_UNKNOWN` is the one state that must never
                  // be rounded up to a refusal, and rewriting the code would round it up.
                  failed(each, {
                    code: failureCode(failure) ?? 'REQUEST_FAILED',
                    message: failureMessage(failure)
                  })
                : each
            )
          )
          say(failureMessage(failure), 'danger')
        })
        .finally(() => {
          setBusy(false)
        })
    },
    [draft, lifecycle, port, say, sessionId]
  )

  const sendKeys = useCallback(
    (bytes: string) => {
      ask(() => port.terminalInput({ session_id: sessionId, bytes })).catch((failure: unknown) => {
        say(failureMessage(failure), 'danger')
      })
    },
    [port, say, sessionId]
  )

  const mine = lifecycle.state.submissions.filter((submission) =>
    isForSession(submission.localId, sessionId)
  )
  const banner = reconnectBanner(connected, mine)
  // A submission whose outcome nobody knows is the one case where sending again could run the
  // same thing twice. Until a receipt settles it, this session sends nothing more.
  const waiting = unresolved(mine)
  const blocked =
    waiting.length > 0
      ? `${waiting.length === 1 ? 'One action has' : `${waiting.length} actions have`} no confirmed outcome yet. Sending again could run it twice.`
      : notSubmittableBecause(draft)
  // While the terminal shows, a draft that is only empty needs no words: Send stands disabled on
  // the field's own line, and attachments are added in the conversation. Every other reason stays.
  const hint = pane === 'terminal' && waiting.length === 0 && draft.state === 'bound' ? null : blocked
  const terminalWarnings = frame === null ? [] : warningsOf(frame, leftBlankOnPhone(frame))

  const field = (
    <textarea
      id={`composer-${sessionId}`}
      rows={pane === 'terminal' ? 1 : undefined}
      value={draft.text}
      placeholder={pane === 'terminal' ? 'Type into the terminal' : 'Message this session'}
      aria-describedby={hint ? `composer-why-${sessionId}` : undefined}
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
  )
  const sendButton = (
    <Button
      tone="primary"
      disabled={!submittable(draft) || busy || waiting.length > 0}
      style={{ minBlockSize: target }}
      onClick={() => {
        send(draft.text)
      }}
    >
      Send
    </Button>
  )
  const lastState = mine.slice(-1).map((submission) => (
    <Badge
      key={submission.localId}
      tone={
        submission.state === 'applied' ? 'success' : submission.state === 'queued' ? 'neutral' : 'accent'
      }
    >
      {describeState(submission.state)}
    </Badge>
  ))

  return (
    <div className="m-session" data-pane={pane}>
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
        {lifecycle.durable ? null : (
          <Banner
            tone="warning"
            title="This device will not keep what you write"
            detail="Storage refused it. The draft is here and you can still send it; it will not survive the application being closed."
          />
        )}
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
            {read !== null && read.refusal !== null ? (
              <Banner
                tone="warning"
                title="This conversation could not be read"
                detail={read.refusal}
              />
            ) : nodes.length === 0 ? (
              // Before the first answer the conversation is being read, which is not the same as
              // empty: the view says which it knows.
              <p className="m-empty">
                {read ? 'Nothing in this conversation yet.' : 'Reading the conversation…'}
              </p>
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
                          ask(() => port.openExternal(url)).catch((failure: unknown) => {
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
          <>
            {terminal?.state === 'ended' ? (
              <Banner
                tone="warning"
                title="This terminal has ended"
                detail={terminal.reason}
                action={
                  <Button data-testid="attach-again" onClick={again}>
                    Attach again
                  </Button>
                }
              />
            ) : null}
            <RawTerminal
              screen={frame}
              busy={terminal === null || terminalWaiting || moving}
              ended={terminal?.state === 'ended'}
              openingKey={openingKey}
              shift={shift}
              roomNow={roomNow}
              onPan={pan}
              surfaceRef={terminalSurface}
              probeRef={cellProbe}
              mode={mode}
              zoom={zoom}
              onZoom={(steps) => {
                setZoom((index) => zoomBy(index, steps))
              }}
              onApplicationScroll={(lines) => {
                sendKeys(lines > 0 ? '\u001b[A'.repeat(Math.min(10, lines)) : '\u001b[B'.repeat(Math.min(10, -lines)))
              }}
            />
          </>
        )}
      </div>

      <div className="m-composer">
        {/* One child, so a composer taller than the room it has scrolls with its bottom in view. */}
        <div className="m-composer-body">
          {pane === 'terminal' ? (
            <>
              <div className="m-terminal-hud">
                <div className="m-terminal-controls">
                  <Badge tone={mode === 'control' ? 'accent' : 'neutral'}>
                    {mode === 'control' ? 'Control' : 'View'}
                  </Badge>
                  <Button
                    onClick={() => {
                      // Taking control shows the program's live screen: a window in the history comes back.
                      if (mode === 'view') live()
                      setMode(mode === 'control' ? 'view' : 'control')
                    }}
                  >
                    {mode === 'control' ? 'Look around' : 'Take control'}
                  </Button>
                  <span>{`Zoom ${Math.round((ZOOM_STEPS[zoom] ?? 1) * 100)}%`}</span>
                  {mode === 'view' ? (
                    <span className="row" role="group" aria-label="Move the window">
                      {PAGE_MOVES.map((move) => (
                        <Button
                          key={move.name}
                          aria-label={`Move the window ${move.name}`}
                          disabled={room === null || room[move.limit] === 0}
                          onClick={() => {
                            if (frame === null) return
                            pan({
                              across: move.across * frame.window.columns,
                              down: move.down * frame.window.rows
                            })
                          }}
                        >
                          {move.label}
                        </Button>
                      ))}
                    </span>
                  ) : null}
                </div>
                {/*
                 * What the view says, in two lines until the person asks for all of it: first the
                 * warnings and where the window is, then what the mode does and how the host presents
                 * the view. A screen reader reads all of it either way.
                 */}
                <div className="m-terminal-status">
                  <div id={statusId} data-expanded={statusOpen}>
                    {terminalWarnings.length > 0 || terminalPosition !== null ? (
                      <p>
                        {terminalWarnings.map((warning) => (
                          <Badge key={warning.id} tone="warning" data-testid={warning.id}>
                            {warning.words}
                          </Badge>
                        ))}
                        {terminalPosition === null ? null : (
                          <span data-testid="terminal-position">{terminalPosition}</span>
                        )}
                      </p>
                    ) : null}
                    <p>
                      <span>{describeMode(mode)}</span>{' '}
                      {terminal === null ? (
                        <span data-testid="terminal-presentation" data-presentation="attaching">
                          {ATTACHING}
                        </span>
                      ) : presented ? (
                        <span data-testid="terminal-presentation" data-presentation={presented.state}>
                          {presented.sentence}
                        </span>
                      ) : null}
                    </p>
                  </div>
                  <Button
                    aria-controls={statusId}
                    aria-expanded={statusOpen}
                    onClick={() => {
                      setStatusOpen((open) => !open)
                    }}
                  >
                    {statusOpen ? 'Less' : 'More'}
                  </Button>
                </div>
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

          {draft.attachments.length > 0 || heldFiles.length > 0 ? (
            <div className="m-attachments">
              {draft.attachments.map((attachment) => (
                <span key={attachment.transferId} className="m-attachment">
                  {attachment.name}
                  <span className="m-row-detail">{describeBytes(attachment.byteLen)}</span>
                </span>
              ))}
              {heldFiles.map(({ picked }) => (
                <span key={`${picked.name}-${picked.byteLen}`} className="m-attachment">
                  {picked.name}
                  <span className="m-row-detail">
                    {`${describeBytes(picked.byteLen)} · held in this screen`}
                  </span>
                </span>
              ))}
            </div>
          ) : null}
          {heldFiles.length > 0 ? (
            <p className="m-hint">
              {heldFiles.length === 1 ? 'That file is' : 'Those files are'} on this device and{' '}
              {heldFiles.length === 1 ? 'has' : 'have'} not been sent: this build has no command that
              carries picked bytes to a host. Nothing has been discarded.
            </p>
          ) : null}

          <label className="visually-hidden" htmlFor={`composer-${sessionId}`}>
            Message this session
          </label>
          {pane === 'terminal' ? (
            // While the terminal shows, the field is one line with Send beside it, as in a
            // message thread: the rows it would take are the terminal's.
            <div className="m-composer-line">
              {field}
              {sendButton}
              {lastState}
            </div>
          ) : (
            field
          )}
          {hint ? (
            <p className="m-hint" id={`composer-why-${sessionId}`}>
              {hint}
            </p>
          ) : null}

          {pane === 'semantic' ? (
            <>
              <AttachmentPicker
                surface={surface}
                onPicked={(files) => {
                  for (const { picked, file } of files) {
                    const admission = admit(picked)
                    if (!admission.admitted) {
                      say(admission.reason, 'danger')
                      continue
                    }
                    setHeldFiles((current) => [...current, { picked, file }])
                  }
                }}
              />

              <div className="m-composer-actions">
                {sendButton}
                {lastState}
              </div>
            </>
          ) : null}
        </div>
      </div>
    </div>
  )
}

/** How many cells the probe that measures the grid's cell holds. */
const PROBE_CELLS = 10

/** One cell of the phone's grid in pixels: a column of the probe, and a line of the grid. */
function cellOf(probe: HTMLSpanElement | null): CellSize | null {
  const box = probe?.getBoundingClientRect()
  if (!probe || !box || box.width <= 0) return null
  const grid = probe.parentElement
  const style = grid ? getComputedStyle(grid) : null
  const line = style?.lineHeight ?? ''
  const size = parseFloat(style?.fontSize ?? '')
  // A line is as tall as the grid's own line height, which a unitless one gives as a multiple.
  const pitch = line.endsWith('px')
    ? parseFloat(line)
    : Number.isFinite(parseFloat(line)) && Number.isFinite(size)
      ? parseFloat(line) * size
      : box.height
  return { width: box.width / PROBE_CELLS, height: pitch > 0 ? pitch : box.height }
}

/** The screen where it rests. */
const AT_REST: Point = { x: 0, y: 0 }

/** The four buttons that move the window a page each way, and the room each one needs. */
const PAGE_MOVES = [
  { name: 'up', label: 'Up', across: 0, down: -1, limit: 'up' },
  { name: 'down', label: 'Down', across: 0, down: 1, limit: 'down' },
  { name: 'left', label: 'Left', across: -1, down: 0, limit: 'left' },
  { name: 'right', label: 'Right', across: 1, down: 0, limit: 'right' }
] as const

/** The session's screen, as cells drawn as text, zoomed by the pinch and moved by a drag in view mode. */
function RawTerminal({
  screen,
  busy,
  ended,
  openingKey,
  shift,
  roomNow,
  onPan,
  surfaceRef,
  probeRef,
  mode,
  zoom,
  onZoom,
  onApplicationScroll
}: {
  readonly screen: TerminalScreen | null
  readonly busy: boolean
  readonly ended: boolean
  /** Which opening of which session the screen is, which a drag belongs to. */
  readonly openingKey: string
  /** Where the screen is drawn from its own place: moved by the moves not yet settled. */
  readonly shift: Cells
  readonly roomNow: () => TerminalRoom | null
  readonly onPan: (cells: Cells) => Cells
  readonly surfaceRef: React.RefObject<HTMLDivElement | null>
  readonly probeRef: React.RefObject<HTMLSpanElement | null>
  readonly mode: ViewMode
  readonly zoom: number
  readonly onZoom: (steps: number) => void
  readonly onApplicationScroll: (lines: number) => void
}): ReactNode {
  // The fingers down in the gesture in progress, each where it is now. An event of any other finger
  // belongs to no gesture and is ignored.
  const pointers = useRef(new Map<number, Point>())
  // Where the gesture began. A drag is the displacement from that origin, not a sum of each move's
  // step: adding steps makes the distance depend on how many events the device sent.
  const start = useRef<{ x: number; y: number; spread: number } | null>(null)
  // The one-finger drag in progress in view mode. The part of it not sent is drawn on a layer of
  // its own, which only the drag and the changes below touch.
  const dragging = useRef<HeldDrag | null>(null)
  const dragLayer = useRef<HTMLDivElement | null>(null)
  // One cell in pixels, measured once laid out at each zoom and screen, for drawing the shift.
  const [cell, setCell] = useState<CellSize | null>(null)
  useLayoutEffect(() => {
    const measured = cellOf(probeRef.current)
    setCell((current) =>
      current?.width === measured?.width && current?.height === measured?.height ? current : measured
    )
  }, [probeRef, zoom, screen])
  const draggable = mode === 'view' && !ended

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
   * Sends the whole cells a drag has crossed, and draws the screen at its new place before the next
   * paint, so the screen and the drag's part on its own layer never show out of step. Drawing it may
   * draw a change of the view that was waiting, whose effects end or begin again the drag, so a
   * handler calls this last, once the drag and its part are stored.
   */
  const sendDragged = (cells: Cells) => {
    if (cells.across === 0 && cells.down === 0) return
    flushSync(() => {
      onPan(cells)
    })
  }

  // Every change of the view a gesture was made in ends it here, at the change itself: another
  // opening, another mode, or the view's end. A change that comes back to where it was is a change
  // too. The fingers still down leave the gesture, so what they do until they lift neither moves
  // the window nor reaches the program.
  useLayoutEffect(() => {
    pointers.current.clear()
    start.current = null
    dragging.current = null
    const layer = dragLayer.current
    if (layer !== null) layer.style.transform = ''
  }, [openingKey, mode, ended])
  // A new cell size: a drag begins again from where the finger is, and its part not sent is dropped.
  const cellWidth = cell?.width
  const cellHeight = cell?.height
  useLayoutEffect(() => {
    const held = dragging.current
    if (held !== null) {
      dragging.current =
        cellWidth === undefined || cellHeight === undefined
          ? null
          : restartDrag(held, { width: cellWidth, height: cellHeight })
    }
    const layer = dragLayer.current
    if (layer !== null) layer.style.transform = ''
  }, [cellWidth, cellHeight])

  /** Takes the gesture's origin again from the fingers that are still down. */
  const rebase = () => {
    const points = [...pointers.current.values()]
    const first = points[0]
    if (!first) {
      start.current = null
      return
    }
    start.current = {
      x: first.x,
      y: first.y,
      spread:
        points.length >= 2 && points[1]
          ? Math.hypot(first.x - points[1].x, first.y - points[1].y)
          : 0
    }
  }

  /** A finger the browser took away: it ends what it was doing and sends nothing. */
  const forget = (pointer: number) => {
    if (!pointers.current.delete(pointer)) return
    rebase()
    if (dragging.current?.pointer === pointer) dropDrag()
  }

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

  const palette = screen?.palette
  const gridName = useId()
  return (
    <div
      className="m-terminal"
      ref={surfaceRef}
      data-mode={mode}
      data-testid="mobile-terminal"
      aria-busy={busy}
      style={
        {
          '--zoom': ZOOM_STEPS[zoom] ?? 1,
          ...(palette
            ? {
                background: `rgb(${palette.background.red}, ${palette.background.green}, ${palette.background.blue})`
              }
            : {}),
          // In view mode the text is not selectable, so a press or a long press starts no selection.
          ...(mode === 'view' ? { userSelect: 'none', WebkitUserSelect: 'none' } : {})
        } as React.CSSProperties
      }
      onPointerDown={(event) => {
        // In view mode the press is the view's: the browser neither starts a selection nor drags
        // away text selected before, which would take the pointer from the drag.
        if (mode === 'view') event.preventDefault()
        event.currentTarget.setPointerCapture(event.pointerId)
        pointers.current.set(event.pointerId, { x: event.clientX, y: event.clientY })
        rebase()
        // One finger in view mode drags the window; a second one ends the drag and pinches.
        if (pointers.current.size === 1 && draggable && cell !== null) {
          const at = { x: event.clientX, y: event.clientY }
          dragging.current = { pointer: event.pointerId, drag: beginDrag(at), cell, last: at }
        } else if (dragging.current !== null) {
          dropDrag()
        }
      }}
      onPointerMove={(event) => {
        if (!pointers.current.has(event.pointerId)) return
        pointers.current.set(event.pointerId, { x: event.clientX, y: event.clientY })
        const held = dragging.current
        if (held === null || held.pointer !== event.pointerId) return
        const room = roomNow()
        if (room === null) return
        const at = { x: event.clientX, y: event.clientY }
        const element = event.currentTarget
        const step = dragTo(held.drag, at, held.cell, room, {
          width: element.clientWidth,
          height: element.clientHeight
        })
        dragging.current = { ...held, drag: step.drag, last: at }
        drawDrag(step.offset)
        sendDragged(step.send)
      }}
      onPointerUp={(event) => {
        if (!pointers.current.has(event.pointerId)) return
        const outcome = routeGesture(mode, gestureFrom(event))
        pointers.current.delete(event.pointerId)
        // A finger leaving changes what the gesture is measured from, so the origin is taken
        // again from the fingers still down. Keeping the old one makes the next gesture jump by
        // whatever the lifted finger had travelled.
        rebase()
        const held = dragging.current
        if (held?.pointer === event.pointerId) {
          // A lifted finger sends only the cells rounding adds.
          dropDrag()
          const room = roomNow()
          if (room === null) return
          sendDragged(releaseDrag(held.drag, { x: event.clientX, y: event.clientY }, held.cell, room))
          return
        }
        if (outcome.kind === 'zoom') onZoom(outcome.steps)
        // In control mode the movement was the program's, so it is handed over rather than used.
        if (outcome.kind === 'application' && outcome.lines !== 0) onApplicationScroll(outcome.lines)
      }}
      onPointerCancel={(event) => {
        forget(event.pointerId)
      }}
      onDragStart={(event) => {
        if (mode === 'view') event.preventDefault()
      }}
      onLostPointerCapture={(event) => {
        forget(event.pointerId)
      }}
    >
      <div ref={dragLayer}>
        <pre
          className="m-terminal-grid"
          data-terminal-grid={gridName}
          style={{
            transform: `translate(${-shift.across * (cell?.width ?? 0)}px, ${
              -shift.down * (cell?.height ?? 0)
            }px)`
          }}
        >
          <span
            ref={probeRef}
            aria-hidden="true"
            style={{ position: 'absolute', visibility: 'hidden', pointerEvents: 'none' }}
          >
            {'M'.repeat(PROBE_CELLS)}
          </span>
          {/* Selected text takes the session's selection colours, as it does on the desktop. */}
          {palette ? <style data-terminal-selection="">{selectionRule(gridName, palette)}</style> : null}
          {screen && palette
            ? screen.lines.map((line, index) => (
                <span key={`${index}-${line.row}`} data-testid="mobile-terminal-line">
                  {stretchesOf(line).map((stretch) =>
                    stretch.piece === null ? (
                      <span key={stretch.column}>{stretch.text}</span>
                    ) : (
                      // A box of exactly the piece's cells that cuts what it holds at its edges, so
                      // no glyph, an italic one's overhang included, reaches the cells beside it.
                      <span
                        key={stretch.column}
                        data-cells={stretch.piece.cells}
                        style={{
                          ...styleOf(stretch.piece.rendition, palette),
                          display: 'inline-block',
                          width: `${stretch.text.length}ch`,
                          overflow: 'hidden',
                          verticalAlign: 'top'
                        }}
                      >
                        {stretch.text}
                      </span>
                    )
                  )}
                  {'\n'}
                </span>
              ))
            : null}
        </pre>
      </div>
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
