/**
 * One session on a phone: the conversation, the raw terminal, and the composer under both.
 *
 * The two views share the draft and the scroll position, so switching between them is switching
 * the view and not starting again. The composer gives local feedback the instant the person sends
 * something and waits for a receipt before it says anything was applied, because a request that
 * reached the host is not a prompt the agent took.
 *
 * The terminal view is the one with a rule in it. It opens in view mode, where a one-finger drag
 * moves the window across the session, up into its history and down its live screen: the screen
 * follows the finger, and comes to rest on the screen the host draws for the window's new place.
 * Control mode is the person's own take of the session's input, labelled as that, and brings a
 * window in the history back to the live screen. Then the program owns the touch, exactly as it owns
 * the wheel on a desktop: a one-finger drag turns its wheel once for each row the finger crosses, at
 * the session's cell under the finger, while it reads the wheel, and the terminal keys and the
 * program's keyboard reach it: while the view controls the program the field is the program's
 * keyboard (`keyboard.ts`), the draft kept for when control ends. Only a pinch zooms, because
 * nothing on the wire carries a pinch, so zooming takes nothing from anyone. A finger that is down
 * when the view changes under it, another opening, mode or life, counts for nothing until it lifts.
 * In view mode a press is the view's alone: whatever the page has selected, the browser starts no
 * selection and no native drag of its own, so a drag always moves the window. Control mode leaves
 * the browser its own way with the text.
 */

import { useCallback, useEffect, useId, useLayoutEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { flushSync } from 'react-dom'

import { useApp, useSession } from '../../app/state'
import { useSessionAgent } from '../../app/agent'
import { useConnectionRights } from '../../app/rights'
import { composerOffers, subjectOf, withheldTotal } from '../../model/agent'
import type { ConversationItem } from '../../model/conversation'
import { Badge, Banner, Button, Segmented } from '../../components/ui'
import { failureCode, failureMessage } from '../../host/port'
import {
  adoptFirstTarget,
  againstCurrent,
  edit,
  notSubmittableBecause,
  retarget,
  startDraft,
  submittable,
  type Draft,
  type DraftAttachment,
  type DraftTarget
} from '../../model/drafts'
import {
  answered,
  answeredState,
  describeState,
  queued,
  reconnectBanner,
  unresolved,
  wasRefused,
  failed
} from '../../model/receipts'
import { renderMarkdown } from '../../markdown/render'
import type { TerminalGrid, TerminalRoom, TerminalScreen, TerminalWheel } from '../../host/port'
import { leftBlankOnPhone, stretchesOf, styleOf } from '../../terminal/cells'
import { selectionRule } from '../../terminal/frame'
import { cellUnder, dragRows, heldTurns, type TerminalCell } from '../../terminal/input'
import {
  ATTACHING,
  modeOf,
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
import { useFocusWhenControlEnds, useOwnControl } from '../../terminal/focus'
import { moveFocus, useProgramKeyboard, type Latched } from '../../terminal/keyboard'
import { focusEscape, readingOf, SENTINEL } from '../../terminal/keys'
import { FALLBACK_GRID, useTerminalView } from '../../terminal/view'
import { AccessoryRow } from '../components/keys'
import { AttachmentPicker } from '../components/picker'
import { afterKey, held as holds, NO_LATCH, pressModifier, rowKey, type Latch } from '../model/accessory'
import { ask } from '../model/call'
import { describeMode } from '../model/gestures'
import { putBack, restOn, type Position } from '../model/keyboard'
import { admit, describeBytes, type Picked } from '../model/media'
import type { Lifecycle } from '../useLifecycle'
import { minimumTarget, type Surface } from '../platform'

/** Which of the two views is showing. */
type Pane = 'semantic' | 'terminal'

/**
 * The shortest session, in multiples of the root text size, that holds the view switch, the
 * conversation's three lines and the whole composer under them. At the base text size these take
 * about 22.4, with a reason of one line; 25 leaves room for a longer one. A shorter session, on a
 * small screen or with a large text size, gets the composer as its line.
 */
const ROOMY_SESSION_REM = 25

/** How long nothing about the keyboard or the page's pan has changed before the field's place is worked out once more. */
const SETTLE_MS = 150

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
  // The session's agent, read from its own worker while this screen is open, into the session's
  // own store: nothing of another session is ever shown under this one.
  const { state: session } = useSession(sessionId)
  const { unread } = useSessionAgent(sessionId)
  const read = session.loaded || unread !== null ? { refusal: unread } : null
  const nodes = useMemo(
    () => session.conversation.nodes.slice(-80).map(readNode),
    [session.conversation.nodes]
  )
  const [zoom, setZoom] = useState(ZOOM_DEFAULT_INDEX)
  const [latch, setLatch] = useState<Latch>(NO_LATCH)
  const [busy, setBusy] = useState(false)
  // Whether the terminal's status shows all it says, rather than its first two lines.
  const [statusOpen, setStatusOpen] = useState(false)
  const statusId = useId()
  const modeButtonId = useId()
  const sendId = useId()
  const attachAgainId = useId()
  const keysHelpId = useId()
  // Whether a software keyboard hides part of the session.
  const [keyboardUp, setKeyboardUp] = useState(false)
  // Whether the session is too short for the conversation's floor under the whole composer.
  const [short, setShort] = useState(false)
  const sessionRef = useRef<HTMLDivElement | null>(null)
  // The files the person took off the draft while they uploaded: what their uploads answer is
  // about files that are no longer there, and nothing is said about them.
  const removedFiles = useRef(new Set<string>())
  const target = minimumTarget(surface)
  // One scroll position per view, kept across a switch: coming back to a view you were reading
  // halfway down and finding the top of it is losing your place.
  const positions = useRef<Record<Pane, number>>({ semantic: 0, terminal: 0 })
  const paneRef = useRef<HTMLDivElement | null>(null)

  // The clock is read once, when this screen opens. Reading it while rendering would make the
  // empty draft a different object on every render and the composer would lose what was typed.
  const [openedAtMs] = useState(() => Date.now())
  const held = lifecycle.state.drafts.find((each) => each.target.sessionId === sessionId)
  // The conversation the session's agent is in now: what a draft is written for, and what it is
  // checked against before it is sent.
  const { instance: liveInstance, binding: liveBinding, capabilities } = session.agent
  const currentTarget: DraftTarget | null = useMemo(
    () =>
      liveInstance === null || liveBinding === null
        ? null
        : {
            sessionId,
            applicationInstanceId: liveInstance,
            agentBindingRevision: liveBinding.binding_revision
          },
    [sessionId, liveInstance, liveBinding]
  )
  // A draft keeps the conversation it was written for; one whose conversation moved on is
  // conflicted, and the person chooses whether it goes to the new one.
  const draft = useMemo(
    () =>
      againstCurrent(
        held ??
          startDraft(
            `draft-${sessionId}`,
            { sessionId, applicationInstanceId: null, agentBindingRevision: null },
            openedAtMs
          ),
        currentTarget
      ),
    [held, sessionId, openedAtMs, currentTarget]
  )
  const rights = useConnectionRights()
  // What the conversation does not show, said above what it does.
  const historyNotes = useMemo(() => {
    const notes: string[] = []
    if (session.agent.unfinished.size > 0) {
      notes.push(
        'An agent that ran here earlier is no longer read. Anything it wrote after this device last read it is not shown.'
      )
    }
    if (session.agent.gap) {
      notes.push('Some of this agent’s earlier entries were no longer kept when this device read them.')
    }
    const withheld = withheldTotal(session.agent.withheld)
    if (withheld > 0) {
      notes.push(
        `At least ${withheld} ${withheld === 1 ? 'entry is' : 'entries are'} outside what this device may see.`
      )
    }
    return notes
  }, [session.agent.unfinished, session.agent.gap, session.agent.withheld])
  const submitOffer = useMemo(
    () =>
      composerOffers({
        known: session.agent.instances !== null,
        binding: liveBinding,
        capabilities,
        rights: rights === null ? null : new Set(rights)
      }).submit,
    [session.agent.instances, liveBinding, capabilities, rights]
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

  /**
   * Records what the person typed on top of the draft as it is stored now.
   *
   * The field's last render is not the newest draft: a rebind the host's answer set off may have
   * bound it since, and writing the render's copy back would undo that. The text is the person's,
   * and everything else is whatever the store holds.
   */
  const typeInto = useCallback(
    (text: string) => {
      lifecycle.setDrafts((drafts) => {
        const stored = drafts.find((each) => each.draftId === draft.draftId)
        const base =
          stored === undefined
            ? draft
            : { ...stored, state: stored.state === 'bound' && draft.state === 'conflicted' ? draft.state : stored.state }
        const next = edit(base, text, Date.now())
        return [...drafts.filter((each) => each.draftId !== draft.draftId), next]
      })
    },
    [lifecycle, draft]
  )

  /** Changes the files on this session's draft, whatever else changed it meanwhile. */
  const changeFiles = useCallback(
    (change: (files: readonly DraftAttachment[]) => readonly DraftAttachment[]) => {
      lifecycle.setDrafts((drafts) => {
        const stored = drafts.find((each) => each.draftId === draft.draftId)
        const base = stored ?? draft
        const next = { ...base, attachments: change(base.attachments) }
        return [...drafts.filter((each) => each.draftId !== draft.draftId), next]
      })
    },
    [lifecycle, draft]
  )

  /**
   * Sends a picked file to the host and keeps it on the draft.
   *
   * The platform gave the file to the page, so the page hands its bytes to native code, which
   * sends them through the same upload a dropped file takes. The file is on the draft from the
   * moment it is picked and stays there, uploading, uploaded or failed, until the person removes
   * it; no prompt is sent without it meanwhile.
   */
  const upload = useCallback(
    (picked: Picked, file: File) => {
      const localId = `file-${Date.now()}-${Math.random()}`
      changeFiles((files) => [
        ...files,
        {
          localId,
          transferId: null,
          name: picked.name,
          byteLen: picked.byteLen,
          mediaType: picked.mediaType,
          presentedAsImage: false,
          upload: 'uploading',
          acceptedUpstream: false
        }
      ])
      const settle = (change: Partial<DraftAttachment>) => {
        changeFiles((files) =>
          files.map((each) => (each.localId === localId ? { ...each, ...change } : each))
        )
      }
      ask(() => file.arrayBuffer())
        .then((buffer) =>
          port.attachmentUploadBytes({ name: picked.name, bytes: new Uint8Array(buffer) }, { sessionId })
        )
        .then((handle) => {
          settle({
            transferId: handle.transfer_id,
            name: handle.original_file_name,
            byteLen: Number(handle.byte_len),
            mediaType: handle.declared_media_type,
            presentedAsImage: handle.presented_as_image,
            upload: 'uploaded'
          })
          if (removedFiles.current.has(localId)) return
          say(
            `${handle.original_file_name} is uploaded and kept with this draft. A prompt sent from here cannot carry it; remove it to send the text on its own.`
          )
        })
        .catch((failure: unknown) => {
          settle({ upload: 'failed' })
          if (removedFiles.current.has(localId)) return
          say(`${picked.name} was not uploaded: ${failureMessage(failure)}`, 'danger')
        })
    },
    [changeFiles, port, say, sessionId]
  )

  // A draft written before the agent was read keeps the first conversation it learns, so that a
  // later move is a conflict rather than a new conversation the text follows.
  useEffect(() => {
    if (held === undefined) return
    const adopted = adoptFirstTarget(held, currentTarget)
    if (adopted !== held) setDraft(adopted)
  }, [held, currentTarget, setDraft])

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
    control,
    takeControl,
    lookAround,
    toProgram,
    controlTake,
    refuse,
    unsent
  } = useTerminalView(port, sessionId, measure, pane === 'terminal')
  const mode = modeOf(control)
  const controlling = control?.state === 'controlling'
  // While the view controls the program, the field's place holds the program's keyboard.
  const typingToProgram = pane === 'terminal' && controlling

  // What the terminal keys hold for the next key, which that key takes: a modifier held for one key
  // is let go as it does. Kept at each commit and as each key takes it, so no key reads it stale.
  const latchNow = useRef(latch)
  useLayoutEffect(() => {
    latchNow.current = latch
  }, [latch])
  const takeLatch = useCallback((): Latch => {
    const now = latchNow.current
    const next = afterKey(now)
    if (next.ctrl !== now.ctrl || next.alt !== now.alt || next.shift !== now.shift) {
      latchNow.current = next
      setLatch(next)
    }
    return now
  }, [])
  const latched = useCallback((): Latched => {
    const now = takeLatch()
    return { control: holds(now, 'ctrl'), alt: holds(now, 'alt') }
  }, [takeLatch])
  const { attach, composing } = useProgramKeyboard({
    controlTake,
    toProgram,
    refuse,
    apple: surface === 'ios',
    latched
  })
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

  // The document measures how much of the screen a software keyboard covers (`--keyboard`). Under
  // the session there is already the shell's padding and its tab bar, which keeps clear of the
  // home indicator, and a keyboard covers those first: the composer is lifted by what it covers
  // beyond them and no more, and while it covers any of the session the terminal's bar yields to
  // the terminal, its keys and the field. The session's own height, in multiples of the root text
  // size, decides whether the whole composer fits under the conversation; a session not laid out,
  // with no height at all, is taken to be roomy.
  useLayoutEffect(() => {
    const element = sessionRef.current
    if (element === null) return
    const root = document.documentElement
    // The keyboard's height the composer's extra lift was worked out for.
    let liftedFor = 0
    let settleTimer = 0
    const moved: Position = { area: null, top: 0 }
    const cover = (again = true) => {
      const style = getComputedStyle(root)
      const covered = parseFloat(style.getPropertyValue('--keyboard')) || 0
      // What lies under the session is measured in the shell's own terms, from where the session
      // ends to where the shell does, as the page lies unscrolled: the shell follows the visual
      // viewport when the page is panned, so a distance to the window's edge would count the pan,
      // and the session moves up by whatever its scrolling area has scrolled.
      const shell = element.closest<HTMLElement>('.m-shell')
      const edge = shell === null ? window.innerHeight : shell.getBoundingClientRect().bottom
      const scrolled = element.closest<HTMLElement>('.m-main')?.scrollTop ?? 0
      const under = Math.max(0, edge - (element.getBoundingClientRect().bottom + scrolled))
      element.style.setProperty('--under-session', `${under}px`)
      setKeyboardUp(covered > under)
      // A session too tall for the room above the keyboard scrolls, and the field being typed into is
      // scrolled to rest on the keyboard's top edge, since the platform's own scroll to it is undone
      // with the shell's pan. What the areas that hold it cannot scroll by is room the composer lacks
      // under the field: it is added to the composer's lift, and taken from it again when the field
      // is higher than it need be. Once the keyboard is gone, what was scrolled is put back.
      if (covered !== liftedFor) {
        liftedFor = covered
        element.style.removeProperty('--lift-more')
        if (covered === 0) putBack(moved)
      }
      const typing = document.activeElement
      const scroller = element.closest<HTMLElement>('.m-main')
      if (
        covered > 0 &&
        shell !== null &&
        scroller !== null &&
        typing instanceof HTMLElement &&
        typing.closest('.m-composer') !== null
      ) {
        let more = parseFloat(element.style.getPropertyValue('--lift-more')) || 0
        for (let pass = 0; pass < 4; pass += 1) {
          // The keyboard's top edge, or the foot of the scrolling area when the keyboard is shorter
          // than what lies under it (a suggestion bar over the tab bar): the field is not taken
          // below what the area shows.
          const off = restOn(typing, Math.min(edge - covered, scroller.getBoundingClientRect().bottom), scroller, moved)
          if (Math.abs(off) <= 0.5 || (off < 0 && more === 0)) break
          more = Math.max(0, more + off)
          element.style.setProperty('--lift-more', `${more}px`)
        }
      }
      // A keyboard takes some time to come up, and the platform pans the page and shrinks its
      // viewport in steps while it does: whatever was worked out in the middle of that is worked out
      // again once nothing has changed for a moment, so it is the final layout the field rests in.
      window.clearTimeout(settleTimer)
      if (again) settleTimer = window.setTimeout(() => cover(false), SETTLE_MS)
      const rem = parseFloat(style.fontSize)
      setShort(element.clientHeight > 0 && rem > 0 && element.clientHeight < ROOMY_SESSION_REM * rem)
    }
    cover()
    const resized = typeof ResizeObserver === 'undefined' ? null : new ResizeObserver(() => cover())
    resized?.observe(element)
    // The keyboard's measure is written on the document's own style.
    const written = new MutationObserver(() => cover())
    written.observe(root, { attributes: true, attributeFilter: ['style'] })
    const onResize = () => cover()
    window.addEventListener('resize', onResize)
    // A field that takes the focus while a keyboard is up is lifted as one that was there before it.
    document.addEventListener('focusin', onResize)
    return () => {
      window.clearTimeout(settleTimer)
      // The shell's scrolling area outlives the session: what this session scrolled it by is undone, so the
      // next view does not open on it.
      putBack(moved)
      resized?.disconnect()
      written.disconnect()
      window.removeEventListener('resize', onResize)
      document.removeEventListener('focusin', onResize)
    }
  }, [])

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
      // What the person wrote goes to the conversation they wrote it for, at the binding revision
      // they wrote it at: the host refuses it if that conversation has moved on since.
      const { applicationInstanceId: instance, agentBindingRevision: revision } = draft.target
      ask(() => {
        if (instance === null || revision === null) {
          // eslint-disable-next-line @typescript-eslint/only-throw-error -- refused as a command's failure is: data
          throw { code: 'UNSUPPORTED_CAPABILITY', message: 'No agent is running in this session.' }
        }
        return port.composerSubmit({
          target: { subject: subjectOf(sessionId, instance), binding_revision: revision },
          draft_id: null,
          text
        })
      })
        .then((answer) => {
          const state = answeredState(answer)
          lifecycle.setSubmissions((current) =>
            current.map((each) =>
              // A receipt says what became of it; the host's own result says it was performed; an
              // answer with neither is an outcome nobody knows, and says so.
              each.localId === submission.localId ? answered(each, answer) : each
            )
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

  // Focus that a terminal key, the program's keyboard or the mode button held when control or the
  // view ends goes to the mode button, which takes control again, or once the view has ended to
  // Attach again: a key that can no longer be pressed, a field that has gone, or a disabled button,
  // is no place to leave it. The same goes for Attach again, unless a pointer pressed it, once the
  // view is open again. While a software keyboard is up the bar holding the mode button is hidden,
  // and the focus goes there once it is back.
  const terminalEnded = terminal?.state === 'ended'
  const attachAgain = useOwnControl(attachAgainId, terminalEnded)
  useFocusWhenControlEnds({
    state: terminalEnded ? 'ended' : (control?.state ?? 'none'),
    heldFor: (element) =>
      element?.closest('.m-accessory') != null ||
      element?.matches('[data-program-keyboard]') === true ||
      element?.id === modeButtonId ||
      attachAgain.held(element),
    destination: () => document.getElementById(terminalEnded ? attachAgainId : modeButtonId)
  })

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
      : (notSubmittableBecause(draft) ?? (submitOffer.offered ? null : submitOffer.reason))
  // The composer is its line, the field with Send beside it, while the terminal shows and on a
  // session too short for the whole composer under the conversation's floor.
  const asLine = pane === 'terminal' || short
  // While the composer is its line, a draft that is only empty needs no words: Send stands disabled
  // beside the field. Every other reason stays, except while the field is the program's keyboard,
  // when the draft waits for control to end.
  const hint = typingToProgram || (asLine && waiting.length === 0 && draft.state === 'bound') ? null : blocked
  const reason = hint ? (
    <p className="m-hint" id={`composer-why-${sessionId}`}>
      {hint}
    </p>
  ) : null
  // Send changes place when the composer changes form, and focus that was on it goes with it: a
  // control taken away from under the focus would leave a keyboard nowhere.
  const lastFocused = useRef<Element | null>(null)
  const wasLine = useRef(asLine)
  useLayoutEffect(() => {
    if (wasLine.current !== asLine) {
      const active = document.activeElement
      if ((active === null || active === document.body) && lastFocused.current?.id === sendId) {
        document.getElementById(sendId)?.focus()
      }
    }
    wasLine.current = asLine
  }, [asLine, sendId])
  const terminalWarnings = frame === null ? [] : warningsOf(frame, leftBlankOnPhone(frame))

  const field = (
    <textarea
      id={`composer-${sessionId}`}
      rows={pane === 'terminal' ? 1 : undefined}
      value={draft.text}
      placeholder={pane === 'terminal' ? 'Type into the terminal' : 'Message this session'}
      aria-describedby={hint ? `composer-why-${sessionId}` : undefined}
      onChange={(event) => {
        typeInto(event.target.value)
      }}
      onKeyDown={(event) => {
        // Control-Tab and Control-Shift-Tab move on from the field as they do from the program's
        // keyboard; Tab and Shift-Tab are left to the platform.
        const escape = focusEscape(readingOf(event.nativeEvent))
        if (escape === null) return
        event.preventDefault()
        moveFocus(event.currentTarget, escape)
      }}
    />
  )
  // The program's keyboard, in the field's place and size. It holds only an invisible character,
  // which hides a placeholder, so it says what it is beside that character while nothing composes.
  const programField = (
    <span className="m-program-keyboard">
      <textarea
        ref={attach}
        data-program-keyboard=""
        rows={1}
        aria-label="Type to the program"
        aria-describedby={keysHelpId}
        defaultValue={SENTINEL}
        autoCapitalize="off"
        autoComplete="off"
        autoCorrect="off"
        spellCheck={false}
      />
      {composing === null ? (
        <span className="m-program-keyboard-hint" aria-hidden="true">
          Type to the program
        </span>
      ) : null}
      <span id={keysHelpId} className="visually-hidden">
        Tab goes to the program; Control-Tab moves on.
      </span>
      <span className="visually-hidden" role="status">
        {unsent}
      </span>
    </span>
  )
  const sendButton = (
    <Button
      id={sendId}
      tone="primary"
      disabled={!submittable(draft) || !submitOffer.offered || busy || waiting.length > 0}
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
    <div
      className="m-session"
      ref={sessionRef}
      data-pane={pane}
      data-keyboard={keyboardUp ? '' : undefined}
      data-composer={asLine ? 'line' : 'whole'}
    >
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
            {historyNotes.length > 0 ? (
              <ul className="m-notes" data-testid="history-notes">
                {historyNotes.map((note) => (
                  <li key={note}>{note}</li>
                ))}
              </ul>
            ) : null}
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
              controlling={controlling}
              programWheel={frame?.wheel ?? null}
              onProgramWheel={(at, turns) => {
                toProgram({
                  kind: 'wheel',
                  column: at.column,
                  line: at.line,
                  turns,
                  shift: false,
                  alt: false,
                  control: false
                }).catch(() => {
                  // A refusal here is control that has just ended, which the view's state says.
                })
              }}
            />
          </>
        )}
      </div>

      <div className="m-composer">
        {/* One child, so a composer taller than the room it has scrolls with its bottom in view. */}
        <div
          className="m-composer-body"
          onFocus={(event) => {
            lastFocused.current = event.target
          }}
        >
          {pane === 'terminal' ? (
            <>
              <div className="m-terminal-hud">
                <div className="m-terminal-controls">
                  <Badge tone={controlling ? 'accent' : 'neutral'}>
                    {controlling ? 'Control' : control?.state === 'taking' ? 'Taking control…' : 'View'}
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
                    {mode === 'control' ? 'Look around' : 'Take control'}
                  </Button>
                  <span>{`Zoom ${Math.round((ZOOM_STEPS[zoom] ?? 1) * 100)}%`}</span>
                  {mode === 'view' ? (
                    // With larger text the four wrap onto a second line rather than run off the screen.
                    <span className="row" role="group" aria-label="Move the window" style={{ flexWrap: 'wrap' }}>
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
                      <span role="status">
                        {describeMode(control ?? { number: 0, state: 'watching', ended: null }, frame?.wheel ?? null)}
                      </span>{' '}
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
                disabled={!controlling}
                onKey={(key, locks) => {
                  const modifier = key.modifier
                  if (modifier !== undefined) {
                    const next = pressModifier(latchNow.current, modifier)
                    latchNow.current = next
                    setLatch(next)
                    return
                  }
                  // A tap is reported once it has ended: its press, then its release, with what the
                  // row held for it.
                  const typed = rowKey(key, takeLatch(), locks)
                  if (typed === null) return
                  for (const event of ['press', 'release'] as const) {
                    toProgram({ kind: 'key', event, ...typed }).catch(() => {
                      // The view says why a key did not reach the program.
                    })
                  }
                }}
              />
            </>
          ) : null}

          {draft.attachments.length > 0 ? (
            <div className="m-attachments" data-testid="draft-attachments">
              {draft.attachments.map((attachment) => (
                <span
                  key={attachment.localId}
                  className="m-attachment"
                  data-upload={attachment.upload}
                >
                  {attachment.name}
                  <span className="m-row-detail">
                    {`${describeBytes(attachment.byteLen)} · ${UPLOAD_WORDS[attachment.upload]}`}
                  </span>
                  <Button
                    tone="quiet"
                    style={{ minBlockSize: target, minInlineSize: target }}
                    aria-label={`Remove ${attachment.name} from this draft`}
                    onClick={() => {
                      removedFiles.current.add(attachment.localId)
                      changeFiles((files) =>
                        files.filter((each) => each.localId !== attachment.localId)
                      )
                    }}
                  >
                    Remove
                  </Button>
                </span>
              ))}
            </div>
          ) : null}

          {typingToProgram ? null : (
            <label className="visually-hidden" htmlFor={`composer-${sessionId}`}>
              Message this session
            </label>
          )}
          {/*
           * Under the terminal the composer keeps its bottom in view, so the reason sits above the
           * field's line: however long it runs, the line keeps the composer's floor.
           */}
          {pane === 'terminal' ? reason : null}
          {typingToProgram && unsent !== null ? (
            // Why an input did not reach the program stands above the program's keyboard, where it
            // stays in view with a software keyboard up, until an input reaches it. The field's own
            // status says it to a screen reader.
            <p className="m-hint m-unsent" aria-hidden="true">
              {unsent}
            </p>
          ) : null}
          {/*
           * The field keeps its place in every form the composer takes, so a change of form never
           * takes it away from under the person typing in it. As the composer's line it is one line
           * with Send beside it, as in a message thread: the rows it would take are the terminal's
           * or the conversation's. While the view controls the program, the program's keyboard
           * takes the field's place, and Send goes with the draft until control ends.
           */}
          <div className={asLine ? 'm-composer-line' : 'm-composer-field'}>
            {typingToProgram ? programField : field}
            {asLine && !typingToProgram ? (
              <>
                {sendButton}
                {lastState}
              </>
            ) : null}
          </div>

          {pane === 'semantic' ? (
            <>
              {reason}
              {draft.state === 'conflicted' && currentTarget !== null ? (
                <Button
                  data-testid="composer-retarget"
                  style={{ minBlockSize: target }}
                  onClick={() => {
                    setDraft(retarget(draft, currentTarget, draft.attachmentId))
                  }}
                >
                  Keep it for the new conversation
                </Button>
              ) : null}
              <AttachmentPicker
                surface={surface}
                onPicked={(files) => {
                  for (const { picked, file } of files) {
                    const admission = admit(picked)
                    if (!admission.admitted) {
                      say(admission.reason, 'danger')
                      continue
                    }
                    upload(picked, file)
                  }
                }}
              />

              {asLine ? null : (
                <div className="m-composer-actions">
                  {sendButton}
                  {lastState}
                </div>
              )}
            </>
          ) : null}
        </div>
      </div>
    </div>
  )
}

/** The zoom step nearest `scale`. */
function nearestZoom(scale: number): number {
  let nearest = 0
  ZOOM_STEPS.forEach((step, index) => {
    if (Math.abs(step - scale) < Math.abs((ZOOM_STEPS[nearest] ?? step) - scale)) nearest = index
  })
  return nearest
}

/** Where a file's upload stands, in words. */
const UPLOAD_WORDS: Readonly<Record<DraftAttachment['upload'], string>> = {
  uploading: 'uploading',
  uploaded: 'uploaded',
  failed: 'not uploaded'
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
  controlling,
  programWheel,
  onProgramWheel
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
  /** Whether the view controls the program, so a drag in control mode turns its wheel. */
  readonly controlling: boolean
  /** Whether a wheel turn reaches the program, or null with no screen. */
  readonly programWheel: TerminalWheel | null
  /** Turns the program's wheel `turns` times at the session's cell `at`. */
  readonly onProgramWheel: (at: TerminalCell, turns: number) => void
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
  // The one-finger drag in control mode, which turns the program's wheel: its finger, where it began
  // counting rows from, the rows it has counted, and where the finger is.
  const turning = useRef<{ pointer: number; origin: number; counted: number; last: Point } | null>(null)
  // The pinch in progress: the zoom step it began at and how far apart the fingers were. While it
  // lasts the screen is scaled with the fingers, and the zoom takes the step nearest where they end.
  const pinching = useRef<{ zoom: number; spread: number } | null>(null)
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

  /**
   * Scales the screen with the fingers while a pinch lasts, from the point between them, so the
   * text grows and shrinks as they move and follows them back if they reverse. Nothing is sent:
   * the zoom changes once, when the pinch ends.
   */
  const drawPinch = (factor: number, around: Point | null) => {
    const layer = dragLayer.current
    const surface = surfaceRef.current
    if (layer === null) return
    if (factor === 1 || around === null || surface === null) {
      layer.style.transform = ''
      layer.style.transformOrigin = ''
      return
    }
    // The point between the fingers, in the layer's own box as it is laid out. The layer's drawn
    // box already carries the scale of the fingers' last movement, and an origin taken from it
    // would move with every movement and carry the text away from under them.
    const frame = surface.getBoundingClientRect()
    const left = frame.left + surface.clientLeft + layer.offsetLeft - surface.scrollLeft
    const top = frame.top + surface.clientTop + layer.offsetTop - surface.scrollTop
    layer.style.transformOrigin = `${around.x - left}px ${around.y - top}px`
    layer.style.transform = `scale(${factor})`
  }

  /** The scale the fingers have reached, as a factor of the zoom the pinch began at. */
  const pinchFactor = (held: { zoom: number; spread: number }): number => {
    const [first, second] = [...pointers.current.values()]
    if (first === undefined || second === undefined || held.spread === 0) return 1
    const spread = Math.hypot(first.x - second.x, first.y - second.y)
    const from = ZOOM_STEPS[held.zoom] ?? 1
    const lowest = ZOOM_STEPS[0]
    const highest = ZOOM_STEPS[ZOOM_STEPS.length - 1] ?? from
    const reached = Math.min(highest, Math.max(lowest, (from * spread) / held.spread))
    return reached / from
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
    turning.current = null
    pinching.current = null
    const layer = dragLayer.current
    if (layer !== null) {
      layer.style.transform = ''
      layer.style.transformOrigin = ''
    }
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
  // A new cell size, or the program starting or stopping to read the wheel: a drag turning its wheel
  // counts again from where the finger is, and the part of a row it had is dropped.
  useLayoutEffect(() => {
    const held = turning.current
    if (held !== null) turning.current = { ...held, origin: held.last.y, counted: 0 }
  }, [cellWidth, cellHeight, programWheel])

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
    if (turning.current?.pointer === pointer) turning.current = null
    if (pinching.current !== null && pointers.current.size < 2) {
      // A pinch the browser ended changes nothing.
      pinching.current = null
      drawPinch(1, null)
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
        // One finger in view mode drags the window, and one in control mode turns the program's
        // wheel; a second one ends either and pinches.
        const at = { x: event.clientX, y: event.clientY }
        if (pointers.current.size === 1 && draggable && cell !== null) {
          dragging.current = { pointer: event.pointerId, drag: beginDrag(at), cell, last: at }
        } else if (pointers.current.size === 1 && mode === 'control' && controlling) {
          turning.current = { pointer: event.pointerId, origin: at.y, counted: 0, last: at }
        } else {
          if (dragging.current !== null) dropDrag()
          turning.current = null
          if (pointers.current.size === 2) {
            pinching.current = { zoom, spread: start.current?.spread ?? 0 }
          }
        }
      }}
      onPointerMove={(event) => {
        if (!pointers.current.has(event.pointerId)) return
        pointers.current.set(event.pointerId, { x: event.clientX, y: event.clientY })
        const pinch = pinching.current
        if (pinch !== null) {
          const [first, second] = [...pointers.current.values()]
          drawPinch(
            pinchFactor(pinch),
            first !== undefined && second !== undefined
              ? { x: (first.x + second.x) / 2, y: (first.y + second.y) / 2 }
              : null
          )
          return
        }
        const turned = turning.current
        if (turned !== null && turned.pointer === event.pointerId) {
          // A turn for each row the finger has crossed since the last, sent at the session's cell
          // under the finger now. Rows it crosses where no cell of the live screen is are dropped.
          const at = { x: event.clientX, y: event.clientY }
          const rows = cell === null ? turned.counted : dragRows(turned.origin, at.y, cell.height)
          turning.current = { ...turned, counted: rows, last: at }
          const turns = heldTurns(rows - turned.counted)
          const surface = surfaceRef.current
          const grid = probeRef.current?.parentElement
          if (turns === 0 || programWheel !== 'reaches' || screen === null || cell === null) return
          if (surface == null || grid == null) return
          const under = cellUnder(at, grid, surface, screen, cell)
          if (under !== null) onProgramWheel(under, turns)
          return
        }
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
        const pinch = pinching.current
        // A pinch ends on the zoom step nearest where the fingers left the text.
        const target = pinch === null ? null : nearestZoom((ZOOM_STEPS[pinch.zoom] ?? 1) * pinchFactor(pinch))
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
        // A finger turning the program's wheel sends nothing more as it lifts: a part of a row is no
        // turn, so a tap sends nothing.
        if (turning.current?.pointer === event.pointerId) turning.current = null
        if (pinch !== null) {
          pinching.current = null
          drawPinch(1, null)
          // The nearest step decides, which is also what keeps an unsteady two-finger touch from
          // changing anything: it ends nearer the step it began at than any other.
          if (target !== null && target !== pinch.zoom) onZoom(target - pinch.zoom)
        }
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
function readNode(item: ConversationItem, index: number): ReadNode {
  if (item.source === 'entry') {
    const { entry } = item
    return {
      id: item.id,
      role:
        entry.kind === 'message'
          ? 'agent'
          : entry.kind === 'tool.finished'
            ? 'tool finished'
            : entry.kind === 'tool.failed'
              ? 'tool failed'
              : entry.kind,
      text: entry.text,
      markdown: entry.kind === 'message'
    }
  }
  const outer = item.node as { id?: string; body?: Record<string, unknown> }
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
