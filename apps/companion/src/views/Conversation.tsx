/**
 * The semantic view: the agent's own history, the requests waiting on the person, and the composer
 * under them.
 *
 * What the conversation shows is what the session's own worker keeps: each entry of the live
 * agent's semantic history, with the identity the worker gave it, so a revision replaces an entry
 * rather than adding one, and a bounded window of them is rendered. A package's declarative
 * presentation adds its nodes beside them, and a node kind this client does not draw renders an
 * unsupported block that can invoke nothing.
 *
 * Nothing in this component owns the session's state. The draft, the history, the window and the
 * pending actions live in the application's per-session store, so switching to the terminal and
 * back keeps them, and one session's state can never appear under another's name.
 *
 * Streamed output does not animate. Text that fades in each time an entry arrives reads as lag, and
 * this is the surface a person watches most.
 */

import {
  memo,
  useCallback,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode
} from 'react'

import type { DocumentNode } from '@kalareach/plugin-sdk'
import type { ActionRight, AgentCommand } from '@kalareach/protocol'
import { promptTextProblem } from '@kalareach/protocol'

import { Badge, Banner, Button, Card, CommitButton, IconButton } from '../components/ui'
import { useApp, useSession } from '../app/state'
import { useSessionAgent } from '../app/agent'
import {
  failureCode,
  failureMessage,
  watch,
  type DroppedFile,
  type SessionSubject
} from '../host/port'
import { renderMarkdown } from '../markdown/render'
import {
  actionableApprovals,
  bindingStateOf,
  composerOffers,
  targetOf,
  withheldTotal,
  type ComposerOffers
} from '../model/agent'
import {
  applyNodes,
  nodeItem,
  nodesAbove,
  setFollowing,
  setWindowStart,
  visibleNodes,
  WINDOW_SIZE,
  type ConversationItem
} from '../model/conversation'
import {
  controlStateOf,
  isRendered,
  readNodeKind,
  visibilityOf,
  type Control,
  type ControlState
} from '../model/controls'
import {
  connectionLost,
  edit,
  notSubmittableBecause,
  readInsertionRefusal,
  submittable,
  type Draft
} from '../model/drafts'
import { FrameBatcher } from '../model/frame'
import { eventIsFor } from '../model/sessions'
import {
  answered,
  answeredState,
  describeState,
  failed,
  outcomeMessage,
  outcomeTone,
  queued,
  reconnectBanner,
  settled,
  wasRefused
} from '../model/receipts'
import type { LaunchSurface } from '../model/pending'
import { ApprovalRequests } from './Approvals'

/** How close to the end still counts as being at it. */
const AT_END_SLACK = 32

/** How close to the top brings more of the document into the window. */
const NEAR_TOP = 64

/** How much of the document one move brings in. */
const WINDOW_STEP = Math.floor(WINDOW_SIZE / 2)

/** The composer's own actions, which the specification names. */
type ComposerAction = 'submit' | 'queue' | 'steer' | 'interrupt'

/**
 * One field of a node body, as text.
 *
 * A node body is whatever the host sent. Anything that is not already a string or a number is not
 * text, and showing `[object Object]` would be worse than showing nothing.
 */
function text(value: unknown): string {
  if (typeof value === 'string') return value
  if (typeof value === 'number') return String(value)
  return ''
}

/** The semantic view of one session. */
export function Conversation({
  sessionId,
  subject,
  connected,
  rights,
  launch,
  onLaunched
}: {
  readonly sessionId: string
  readonly subject: SessionSubject
  readonly connected: boolean
  /** The rights this connection holds, or null when it has not been told. */
  readonly rights: readonly ActionRight[] | null
  /** The launch surface as it was read, and the prompt's generation as the view knows it now. */
  readonly launch: { readonly surface: LaunchSurface; readonly promptGeneration: string } | null
  readonly onLaunched: () => void
}): ReactNode {
  const { port, say } = useApp()
  const { state, update } = useSession(sessionId)
  const { unread, refresh } = useSessionAgent(sessionId)
  const [insertion, setInsertion] = useState<string | null>(null)
  // Why the host's event stream could not be followed, under the visit it was opened in: a failure
  // from an earlier visit to this session is not shown on a return to it.
  const visit = useMemo(() => ({ sessionId }), [sessionId])
  const [unfollowed, setUnfollowed] = useState<{
    readonly visit: object
    readonly words: string
  } | null>(null)
  const scroller = useRef<HTMLDivElement | null>(null)
  const anchor = useRef<{ nodeId: string; offsetTop: number } | null>(null)
  const agent = state.agent

  // A package's presentation arrives as nodes on the host's event stream. One batch per animation
  // frame: forty in one tick are one render, and the composer keeps taking keystrokes meanwhile.
  const batcher = useMemo(
    () =>
      new FrameBatcher<DocumentNode>((batch) => {
        update((current) => ({
          ...current,
          conversation: applyNodes(current.conversation, batch.map(nodeItem))
        }))
      }),
    [update]
  )

  /**
   * Gives a refused submission's text back to the person who wrote it.
   *
   * The composer may already hold something else by the time a refusal arrives, and overwriting it
   * would lose that instead. So the text goes back when the composer is empty, and when it is not
   * it is offered: the submission keeps its text either way, and nothing the person wrote is gone.
   */
  const returnRefusedText = useCallback(
    (localId: string) => {
      update((current) => {
        const refused = current.submissions.find(
          (submission) => submission.localId === localId
        )
        if (!refused || refused.text.length === 0) return current
        if (current.draft.text.length > 0) return current
        return { ...current, draft: edit(current.draft, refused.text, Date.now()) }
      })
    },
    [update]
  )

  // The host's event stream carries a package's presentation nodes and late receipts. Each is
  // taken as it arrives, for this session only.
  useEffect(() => {
    const watching = watch(
      [
        port.subscribe((event) => {
          const body = event.body as { kind?: string; node?: DocumentNode; receipt?: unknown }
          // An event belongs to the stream it names. A view showing one session ignores another's
          // rather than folding it into what the person is looking at.
          if (body.kind === 'node' && body.node && eventIsFor(event.stream_id, sessionId)) {
            batcher.push(body.node)
          }
          if (body.kind === 'receipt' && body.receipt) {
            const receipt = body.receipt as Parameters<typeof settled>[1]
            let refused: string | null = null
            update((current) => ({
              ...current,
              submissions: current.submissions.map((submission) => {
                if (submission.actionId !== receipt.action_id) return submission
                const next = settled(submission, receipt)
                if (wasRefused(next.state)) refused = next.localId
                return next
              })
            }))
            // A refusal that arrives later is the same refusal: the text comes back then too.
            if (refused) returnRefusedText(refused)
          }
        })
      ],
      undefined,
      (failure) => {
        setUnfollowed({ visit, words: failureMessage(failure) })
      }
    )
    return () => {
      watching.stop()
      batcher.discard()
    }
  }, [port, sessionId, visit, batcher, update, returnRefusedText])

  const offers = useMemo(
    () =>
      composerOffers({
        binding: agent.binding,
        capabilities: agent.capabilities,
        rights: rights === null ? null : new Set(rights)
      }),
    [agent.binding, agent.capabilities, rights]
  )
  const waitingOnPerson =
    agent.instances === null ? null : actionableApprovals(agent.resources).length > 0

  // What a control's visibility is decided from: every fact this device has been told.
  const controlState: ControlState = useMemo(
    () =>
      controlStateOf({
        capabilities: agent.capabilities,
        rights,
        bindingState:
          waitingOnPerson === null ? null : bindingStateOf(agent.binding, waitingOnPerson),
        waitingOnPerson,
        presentNodes: new Set(state.conversation.nodes.map((item) => item.id)),
        compact: false
      }),
    [agent.capabilities, agent.binding, rights, waitingOnPerson, state.conversation.nodes]
  )

  const send = useCallback(
    (action: ComposerAction) => {
      const binding = agent.binding
      const instance = agent.instance
      if (binding === null || instance === null) return
      const typed = state.draft.text
      if (action !== 'interrupt' && promptTextProblem(typed) === 'too-long') {
        say('That is longer than one prompt carries. It is kept here.', 'danger')
        return
      }
      const label = typed.trim() || action
      const local = queued(`s-${Date.now()}-${Math.random()}`, label, Date.now(), typed)
      const clears = action === 'submit' || action === 'queue'

      // Local feedback first: the entry appears as queued and the composer clears. The completion
      // feedback below waits for the host's answer.
      update((current) => ({
        ...current,
        submissions: [...current.submissions, local],
        draft: clears ? edit(current.draft, '', Date.now()) : current.draft
      }))

      const target = targetOf(sessionId, instance, binding)
      const turn = binding.turn_id ?? ''
      const call =
        action === 'submit'
          ? port.composerSubmit({ target, draft_id: null, text: typed })
          : action === 'queue'
            ? port.composerQueue({ target, draft_id: null, text: typed })
            : action === 'steer'
              ? port.composerSteer({ target, turn_id: turn, text: typed })
              : port.composerInterrupt({ target, turn_id: turn })

      call
        .then((result) => {
          const outcome = answeredState(result)
          update((current) => ({
            ...current,
            submissions: current.submissions.map((submission) =>
              submission.localId === local.localId ? answered(submission, result) : submission
            )
          }))
          if (wasRefused(outcome)) {
            returnRefusedText(local.localId)
            say('The host did not take that. It is kept here.', 'danger')
          }
          if (outcome === 'unknown') {
            say('The host could not confirm what became of that.', 'danger')
          }
        })
        .catch((error: unknown) => {
          const code = failureCode(error) ?? 'UNKNOWN'
          update((current) => ({
            ...current,
            submissions: current.submissions.map((submission) =>
              submission.localId === local.localId
                ? failed(submission, { code, message: failureMessage(error) })
                : submission
            )
          }))
          returnRefusedText(local.localId)
          say(failureMessage(error), 'danger')
        })
        .finally(refresh)
    },
    [port, sessionId, agent.binding, agent.instance, state.draft.text, update, say, returnRefusedText, refresh]
  )

  /**
   * A dropped file becomes an attachment in three steps, and they stay three.
   *
   * The transfer publishes a verified handle. The insertion binds that handle to the draft. The
   * submission is a separate act the person performs. Section 12 keeps them apart because a failed
   * insertion must leave the completed upload and the draft alone, and because only upstream
   * evidence makes an attachment accepted by an agent. A file is sent only where the agent says it
   * takes attachments now.
   */
  const attach = useCallback(
    (files: readonly DroppedFile[]) => {
      for (const file of files) {
        if (!offers.attach.offered) {
          setInsertion(`${file.name} was not sent: ${offers.attach.reason ?? 'this agent takes no attachments here.'}`)
          continue
        }
        const path = file.path
        if (!path) {
          setInsertion('That file was not given to this window, so it was not sent.')
          continue
        }
        port
          .attachmentUpload(path, subject)
          .then((handle) => {
            // The upload is done and the handle is verified. It is kept whatever the insertion
            // does next.
            update((current) => ({
              ...current,
              draft: {
                ...current.draft,
                attachments: [
                  ...current.draft.attachments,
                  {
                    transferId: handle.transfer_id,
                    name: handle.original_file_name,
                    byteLen: Number(handle.byte_len),
                    mediaType: handle.declared_media_type,
                    presentedAsImage: handle.presented_as_image,
                    acceptedUpstream: false
                  }
                ]
              }
            }))
            return port
              .draftAddAttachment(
                {
                  draft_id: state.draft.draftId,
                  transfer_id: handle.transfer_id,
                  insertion_method: 'typed_submission'
                },
                subject
              )
              .then((result) => {
                // Only an applied answer says the attachment reached the draft. The upload is
                // done either way, and the handle above is kept.
                say(
                  outcomeMessage(`${handle.original_file_name} attached`, result),
                  outcomeTone(result)
                )
              })
              .catch((error: unknown) => {
                const refusal = readInsertionRefusal(failureCode(error) ?? 'UNKNOWN')
                setInsertion(refusal.fallback)
              })
          })
          .catch((error: unknown) => {
            setInsertion(`${file.name} was not sent: ${failureMessage(error)}`)
          })
      }
    },
    [port, state.draft.draftId, subject, update, say, offers.attach]
  )

  useEffect(() => watch([port.onFilesDropped(attach)]).stop, [port, attach])

  // Losing contact removes the association, not the draft. That is a fact about the connection, so
  // it is derived here rather than written into the stored draft: the text, the revision and the
  // attachments are untouched, and a rebind is still the explicit act it has to be.
  const presented = useMemo(
    () => (connected ? state.draft : connectionLost(state.draft)),
    [connected, state.draft]
  )

  const banner = reconnectBanner(connected, state.submissions)
  const rendered = useMemo(() => visibleNodes(state.conversation), [state.conversation])
  const hidden = nodesAbove(state.conversation)

  const openLink = useCallback(
    (url: string) => {
      port
        .openExternal(url)
        .then((approved) => {
          say(`Opened ${approved.host ?? approved.url}.`)
        })
        .catch((error: unknown) => {
          say(failureMessage(error), 'danger')
        })
    },
    [port, say]
  )

  const importImage = useCallback(
    (url: string) => {
      port
        .importRemoteImage(url)
        .then((imported) => {
          const blob = new Blob([new Uint8Array(imported.bytes)], { type: imported.media_type })
          const held = URL.createObjectURL(blob)
          update((current) => ({
            ...current,
            images: new Map(current.images).set(url, held)
          }))
        })
        .catch((error: unknown) => {
          say(failureMessage(error), 'danger')
        })
    },
    [port, update, say]
  )

  const invoke = useCallback(
    (control: Control) => {
      port
        .pluginActionInvoke(
          { action_id: control.action_id, control_revision: control.revision },
          subject
        )
        .then((result) => {
          say(outcomeMessage(control.label, result), outcomeTone(result))
        })
        .catch((error: unknown) => {
          say(failureMessage(error), 'danger')
        })
    },
    [port, subject, say]
  )

  /**
   * Decides whether the view is still following, and brings more of the document into the window
   * when the reader reaches either edge of it.
   *
   * Following is what the scroll position says, not a setting: a person who has scrolled up is
   * reading, and new output must not pull them away from it.
   *
   * Moving the window changes what is laid out, so the node the reader is looking at is recorded
   * and the scroll position is corrected by how far it moved once the new window is laid out.
   * Without that the view jumps, and a jump at the top of the content is indistinguishable from the
   * content being taken away.
   */
  const onScroll = useCallback(() => {
    const element = scroller.current
    if (!element) return
    const atBottom = atScrollerEnd(element)
    const atTop = element.scrollTop < NEAR_TOP
    update((current) => {
      const conversation = current.conversation
      const last = lastWindowStart(conversation.nodes.length)

      if (atBottom && conversation.windowStart >= last) {
        // The bottom of the last window is the live end, and only there.
        return { ...current, conversation: setFollowing(conversation, true) }
      }

      const stopped = setFollowing(conversation, false)
      if (atBottom && stopped.windowStart < last) {
        // The bottom of a window that is not the last is more document, not the end of it.
        anchor.current = anchorOf(element)
        return {
          ...current,
          conversation: setWindowStart(stopped, Math.min(last, stopped.windowStart + WINDOW_STEP))
        }
      }
      if (atTop && stopped.windowStart > 0) {
        anchor.current = anchorOf(element)
        return {
          ...current,
          conversation: setWindowStart(stopped, Math.max(0, stopped.windowStart - WINDOW_STEP))
        }
      }
      return { ...current, conversation: stopped }
    })
  }, [update])

  // The correction for a window that moved: the node the reader was looking at goes back to the
  // pixel it was on. A sliding window does not change how tall the content is, so a correction
  // computed from the height would be zero and the reader would be moved without being told.
  //
  // Whether the view is at the live end is settled here as well as on scroll. A view that is at
  // the end is following, and the position can reach the end without a scroll event: laying out a
  // shorter window, or content that does not fill the viewport, both do it.
  useLayoutEffect(() => {
    const element = scroller.current
    if (!element) return
    const held = anchor.current
    if (held) {
      anchor.current = null
      const node = element.querySelector<HTMLElement>(`[data-node-id="${cssEscape(held.nodeId)}"]`)
      if (node) element.scrollTop += node.offsetTop - held.offsetTop
    }
    update((current) => {
      const atEnd =
        atScrollerEnd(element) &&
        current.conversation.windowStart >= lastWindowStart(current.conversation.nodes.length)
      return atEnd
        ? { ...current, conversation: setFollowing(current.conversation, true) }
        : current
    })
  }, [state.conversation.windowStart, state.conversation.nodes.length, update])

  const noAgent = agent.instances !== null && agent.instance === null
  const withheld = withheldTotal(agent.withheld)

  return (
    <div className="conversation" data-testid="conversation">
      {banner ? <Banner tone={banner.tone} title={banner.title} detail={banner.detail} /> : null}

      {unread !== null ? (
        <div data-testid="conversation-unread">
          <Banner tone="warning" title="This conversation could not be read" detail={unread} />
        </div>
      ) : null}

      {unfollowed?.visit === visit ? (
        <div data-testid="conversation-unfollowed">
          <Banner
            tone="warning"
            title="Live updates are not reaching this view"
            detail={`${unfollowed.words} What packages show here and late answers wait until the session is opened again; the agent's history is still read.`}
          />
        </div>
      ) : null}

      {state.submissions.length > 0 ? (
        <ul className="pending-actions" data-testid="pending-actions">
          {state.submissions.map((submission) => (
            <li key={submission.localId} data-state={submission.state}>
              <Badge
                tone={
                  submission.state === 'applied'
                    ? 'success'
                    : submission.state === 'queued'
                      ? 'neutral'
                      : submission.state === 'sent'
                        ? 'accent'
                        : 'danger'
                }
              >
                {describeState(submission.state)}
              </Badge>
              <span className="small faint">{submission.label}</span>
            </li>
          ))}
        </ul>
      ) : null}

      <div
        className="conversation-scroll"
        ref={scroller}
        onScroll={onScroll}
        data-testid="conversation-scroll"
        data-following={state.conversation.following ? 'true' : 'false'}
        data-window-start={state.conversation.windowStart}
      >
        {agent.gap || withheld > 0 || hidden > 0 ? (
          <div className="history-edge" data-testid="history-notes">
            {agent.gap ? (
              <p className="small faint">
                Some of this agent’s earlier entries were no longer kept when this device read
                them.
              </p>
            ) : null}
            {withheld > 0 ? (
              <p className="small faint" data-testid="withheld">
                {withheld} {withheld === 1 ? 'entry is' : 'entries are'} outside what
                this device may see.
              </p>
            ) : null}
          </div>
        ) : null}

        {noAgent && state.conversation.nodes.length === 0 ? (
          <div className="empty-state" data-testid="no-agent">
            <h2>No agent is running here</h2>
            <p>This session runs a shell. The terminal shows what it is doing.</p>
          </div>
        ) : null}

        <Document
          items={rendered}
          controlState={controlState}
          images={state.images}
          onOpenLink={openLink}
          onImportImage={importImage}
          onInvoke={invoke}
        />
      </div>

      <ApprovalRequests sessionId={sessionId} onAnswered={refresh} />

      {launch?.surface.prompt_is_empty ? (
        <LaunchSurfaceView
          surface={launch.surface}
          promptGeneration={launch.promptGeneration}
          subject={subject}
          sessionId={sessionId}
          connected={connected}
          onLaunched={onLaunched}
        />
      ) : null}

      <Composer
        draft={presented}
        connected={connected}
        offers={offers}
        commands={agent.commands}
        insertion={insertion}
        onChange={(next) => {
          update((current) => ({ ...current, draft: edit(current.draft, next, Date.now()) }))
        }}
        onAction={send}
      />
    </div>
  )
}

/** Whether the view is at the bottom of what is rendered, which is not the same as the live end. */
function atScrollerEnd(element: HTMLElement): boolean {
  return element.scrollHeight - element.scrollTop - element.clientHeight < AT_END_SLACK
}

/** Where the window sits when it is showing the live end. */
function lastWindowStart(total: number): number {
  return Math.max(0, total - WINDOW_SIZE)
}

/**
 * The node the reader is looking at, and where it is.
 *
 * The first node whose bottom is below the top of the viewport: that is the one a person's eye is
 * on, and it is the one that must not move.
 */
function anchorOf(element: HTMLElement): { nodeId: string; offsetTop: number } | null {
  const nodes = element.querySelectorAll<HTMLElement>('[data-node-id]')
  for (const node of nodes) {
    if (node.offsetTop + node.offsetHeight > element.scrollTop) {
      const nodeId = node.dataset.nodeId
      if (nodeId) return { nodeId, offsetTop: node.offsetTop }
    }
  }
  return null
}

/** A node identifier, as a selector may carry it. */
function cssEscape(value: string): string {
  return typeof CSS !== 'undefined' && typeof CSS.escape === 'function'
    ? CSS.escape(value)
    : value.replace(/["\\]/g, '\\$&')
}

/**
 * The rendered document.
 *
 * It is memoised on purpose, and the memo is the point rather than an optimisation. A keystroke in
 * the composer changes the draft and nothing else, so the document must not re-render for it: with
 * a large history that is the difference between a keystroke costing microseconds and costing more
 * than a frame. Everything this depends on is a value that changes only when the document does.
 */
const Document = memo(function Document({
  items,
  controlState,
  images,
  onOpenLink,
  onImportImage,
  onInvoke
}: {
  readonly items: readonly ConversationItem[]
  readonly controlState: ControlState
  readonly images: ReadonlyMap<string, string>
  readonly onOpenLink: (url: string) => void
  readonly onImportImage: (url: string) => void
  readonly onInvoke: (control: Control) => void
}): ReactNode {
  return (
    <>
      {items.map((item) =>
        item.source === 'entry' ? (
          <EntryView
            key={item.id}
            item={item}
            images={images}
            onOpenLink={onOpenLink}
            onImportImage={onImportImage}
          />
        ) : (
          <NodeView
            key={item.id}
            node={item.node}
            controlState={controlState}
            images={images}
            onOpenLink={onOpenLink}
            onImportImage={onImportImage}
            onInvoke={onInvoke}
          />
        )
      )}
    </>
  )
})

/** What each kind of history entry is called beside it. */
function entryLabel(kind: string): string {
  switch (kind) {
    case 'tool.finished':
      return 'Tool finished'
    case 'tool.failed':
      return 'Tool failed'
    case 'notification':
      return 'Notice'
    default:
      return kind
  }
}

/**
 * One entry of the agent's history.
 *
 * A message is the agent's own words and goes through the allowlisted Markdown renderer, which
 * draws text and never fetches an image. The start, continuation and end of a thread mark where the
 * conversation moved. A tool's outcome and a notification are one line each. Any other kind, which
 * a connector's presentation may name, is shown as its text under its own name: an entry carries
 * text and never an action.
 */
const EntryView = memo(function EntryView({
  item,
  images,
  onOpenLink,
  onImportImage
}: {
  readonly item: Extract<ConversationItem, { readonly source: 'entry' }>
  readonly images: ReadonlyMap<string, string>
  readonly onOpenLink: (url: string) => void
  readonly onImportImage: (url: string) => void
}): ReactNode {
  const { entry } = item
  const omitted = Number(entry.omitted_text_bytes)
  const cut =
    omitted > 0 ? (
      <p className="small faint" data-testid="entry-cut">
        {omitted.toLocaleString()} more bytes of this entry were not carried.
      </p>
    ) : null
  if (entry.kind === 'message') {
    return (
      <article className="message" data-node-id={item.id} data-kind="message">
        <div className="message-content markdown">
          {renderMarkdown(entry.text, {
            openLink: onOpenLink,
            importImage: onImportImage,
            importedImages: images
          })}
          {cut}
        </div>
      </article>
    )
  }
  if (entry.kind.startsWith('thread.')) {
    return (
      <div className="thread-mark" data-node-id={item.id} data-kind={entry.kind}>
        <span className="small faint">{entry.text}</span>
        {cut}
      </div>
    )
  }
  if (entry.kind === 'tool.finished' || entry.kind === 'tool.failed' || entry.kind === 'notification') {
    return (
      <div className="tool-result" data-node-id={item.id} data-kind={entry.kind}>
        <Badge tone={entry.kind === 'tool.failed' ? 'danger' : entry.kind === 'notification' ? 'neutral' : 'accent'}>
          {entryLabel(entry.kind)}
        </Badge>
        <span className="small">{entry.text}</span>
        {cut}
      </div>
    )
  }
  return (
    <article className="message" data-node-id={item.id} data-kind={entry.kind}>
      <div className="message-content">
        <p className="eyebrow">{entryLabel(entry.kind)}</p>
        <p className="entry-text">{entry.text}</p>
        {cut}
      </div>
    </article>
  )
})

/** One document node. */
const NodeView = memo(function NodeView({
  node,
  controlState,
  images,
  onOpenLink,
  onImportImage,
  onInvoke
}: {
  readonly node: DocumentNode
  readonly controlState: ControlState
  readonly images: ReadonlyMap<string, string>
  readonly onOpenLink: (url: string) => void
  readonly onImportImage: (url: string) => void
  readonly onInvoke: (control: Control) => void
}): ReactNode {
  const body = node.body as Record<string, unknown>
  const kind = readNodeKind(body)

  if (!isRendered(kind)) {
    // An unknown node renders as itself and invokes nothing. There is no branch here that could
    // turn a shape this client does not understand into an action.
    return (
      <article className="message unsupported" data-testid="unsupported-node" data-kind={kind}>
        <div className="message-content">
          <p className="muted small">
            This session sent content this application does not know how to show. It carries no
            action.
          </p>
        </div>
      </article>
    )
  }

  switch (kind) {
    case 'message':
      return (
        <article className="message" data-node-id={node.id} data-kind="message">
          <div className="message-content">
            <div className="message-header">
              <strong>{text(body.author)}</strong>
            </div>
            <p>{text(body.text)}</p>
          </div>
        </article>
      )

    case 'markdown':
      return (
        <article className="message" data-node-id={node.id} data-kind="markdown">
          <div className="message-content markdown">
            {renderMarkdown(text(body.source), {
              openLink: onOpenLink,
              importImage: onImportImage,
              importedImages: images
            })}
          </div>
        </article>
      )

    case 'tool':
      return (
        <div className="tool-result" data-node-id={node.id} data-kind="tool">
          <Badge tone={body.outcome === 'failed' ? 'danger' : 'accent'}>
            {text(body.outcome)}
          </Badge>
          <strong>{text(body.name)}</strong>
          <span className="muted small">{text(body.summary)}</span>
        </div>
      )

    case 'diff': {
      const files = Array.isArray(body.files) ? body.files : []
      return (
        <div className="diff-summary" data-node-id={node.id} data-kind="diff">
          {files.map((file, index) => {
            const entry = file as { path?: string; added?: number; removed?: number }
            return (
              <div className="divided-row" key={`${node.id}-${index}`}>
                <span className="mono spacer">{entry.path}</span>
                <span className="success-text small">+{entry.added ?? 0}</span>
                <span className="danger-text small">-{entry.removed ?? 0}</span>
              </div>
            )
          })}
        </div>
      )
    }

    case 'progress':
      return (
        <div className="progress-node" data-node-id={node.id} data-kind="progress">
          <span className="small muted">{text(body.label)}</span>
        </div>
      )

    case 'approval_ref':
      return (
        <Card data-node-id={node.id} data-kind="approval_ref">
          <div className="card-body">
            <h3>A decision is waiting</h3>
            <p className="muted small">
              This turn is waiting on an approval. It is in the attention inbox, with the command it
              would run.
            </p>
          </div>
        </Card>
      )

    case 'terminal_ref':
      return (
        <div className="terminal-ref" data-node-id={node.id} data-kind="terminal_ref">
          <span className="small muted">This turn wrote to the terminal.</span>
        </div>
      )

    case 'form': {
      const submit = body.submit as Control | undefined
      return (
        <Card data-node-id={node.id} data-kind="form">
          <div className="card-header">
            <h3>{text(body.title)}</h3>
          </div>
          <div className="card-body">
            <FormFields fields={body.fields} />
            {submit ? (
              <ControlButton control={submit} state={controlState} onInvoke={onInvoke} />
            ) : null}
          </div>
        </Card>
      )
    }

    case 'attachment':
      return (
        <div className="attachment-chip" data-node-id={node.id} data-kind="attachment">
          <span>{text(body.name)}</span>
          <span className="faint small">{text(body.size_bytes)} bytes</span>
        </div>
      )

    case 'action_button':
    case 'action_group':
    case 'command_palette':
    case 'attachment_entry': {
      const controls = controlsOf(body)
      return (
        <div className="control-group" data-node-id={node.id} data-kind={kind}>
          {typeof body.label === 'string' ? <p className="eyebrow">{body.label}</p> : null}
          <div className="row wrap">
            {controls.map((control) => (
              <ControlButton
                key={control.id}
                control={control}
                state={controlState}
                onInvoke={onInvoke}
              />
            ))}
          </div>
        </div>
      )
    }

    default:
      return null
  }
})

/**
 * A form's fields, drawn from the parameter schema the package published.
 *
 * Standard components, nothing the package supplied as markup. A field whose type this client does
 * not draw is named and left blank rather than guessed at.
 */
function FormFields({ fields }: { readonly fields: unknown }): ReactNode {
  const entries =
    typeof fields === 'object' &&
    fields !== null &&
    Array.isArray((fields as { parameters?: unknown }).parameters)
      ? ((fields as { parameters: unknown[] }).parameters as Record<string, unknown>[])
      : []
  if (entries.length === 0) return null
  return (
    <div data-testid="form-fields">
      {entries.map((field, index) => {
        const name = text(field.name) || `field-${index}`
        const label = text(field.label) || name
        // The declaration's kind is a tagged object, and its tag is what a client draws from.
        const kind =
          typeof field.kind === 'object' && field.kind !== null
            ? text((field.kind as { type?: unknown }).type)
            : ''
        return (
          <label className="form-field" key={name}>
            <span>{label}</span>
            {kind === 'boolean' ? (
              <input type="checkbox" name={name} />
            ) : kind === 'integer' ? (
              <input type="number" name={name} />
            ) : kind === 'choice' ? (
              <select name={name}>
                {(Array.isArray((field.kind as { choices?: unknown }).choices)
                  ? ((field.kind as { choices: Record<string, unknown>[] }).choices)
                  : []
                ).map((choice, position) => (
                  <option key={text(choice.id) || position} value={text(choice.id)}>
                    {text(choice.label) || text(choice.id)}
                  </option>
                ))}
              </select>
            ) : (
              <input type="text" name={name} />
            )}
            {text(field.description) ? (
              <span className="form-hint">{text(field.description)}</span>
            ) : null}
          </label>
        )
      })}
    </div>
  )
}

function controlsOf(body: Record<string, unknown>): readonly Control[] {
  if (Array.isArray(body.controls)) return body.controls as Control[]
  if (body.control) return [body.control as Control]
  if (body.contribute) return [body.contribute as Control]
  if (body.submit) return [body.submit as Control]
  return []
}

/** One declarative control, as a standard component. */
function ControlButton({
  control,
  state,
  onInvoke
}: {
  readonly control: Control
  readonly state: ControlState
  readonly onInvoke: (control: Control) => void
}): ReactNode {
  const visibility = visibilityOf(control, state)
  if (visibility.kind === 'hidden') return null
  return (
    <CommitButton
      tone={control.priority === 'primary' ? 'primary' : 'default'}
      disabled={!visibility.enabled}
      title={visibility.disabledReason ?? undefined}
      aria-description={control.accessible_description}
      data-control-id={control.id}
      onCommit={() => {
        onInvoke(control)
      }}
    >
      {control.label}
    </CommitButton>
  )
}

/**
 * The launch surface at a verified empty prompt.
 *
 * Every button carries the prompt generation it was drawn at. A generation that moved disables them
 * all, because the prompt the person was looking at is not the prompt that is there now. Nothing
 * here pastes: a launch is an installed command, not typed characters.
 */
function LaunchSurfaceView({
  surface,
  promptGeneration,
  subject,
  sessionId,
  connected,
  onLaunched
}: {
  readonly surface: LaunchSurface
  /** The prompt's generation now, which a read that answered late may already be behind. */
  readonly promptGeneration: string
  readonly subject: SessionSubject
  readonly sessionId: string
  readonly connected: boolean
  readonly onLaunched: () => void
}): ReactNode {
  const { port, say } = useApp()
  // The generation these buttons were drawn at. A host that moved the prompt on makes them stale,
  // and reading the surface again is what makes them usable: a person looks at the prompt, and the
  // refreshed proof is what re-enables the buttons.
  const [drawnAt, setDrawnAt] = useState(surface.prompt_generation)
  const stale = drawnAt !== promptGeneration || !connected

  return (
    <section className="launch-surface" data-testid="launch-surface" data-stale={stale}>
      <p className="eyebrow">Start something here</p>
      <div className="row wrap">
        {surface.profiles.map((profile) => {
          const missing = profile.executable === null
          return (
            <CommitButton
              key={profile.profile_id}
              data-profile={profile.profile_id}
              disabled={stale || missing}
              title={
                stale
                  ? 'The prompt changed. Look at it before starting anything.'
                  : missing
                    ? `${profile.label} is not installed in this environment.`
                    : `${profile.executable}${profile.version ? ` · ${profile.version}` : ''}`
              }
              onCommit={() => {
                port
                  .shellLaunch(
                    {
                      session_id: sessionId,
                      command: { arguments: [...profile.arguments] },
                      expected_prompt_generation: promptGeneration,
                      expected_buffer_revision: surface.buffer_revision
                    },
                    subject
                  )
                  .then((result) => {
                    say(outcomeMessage(`${profile.label} started`, result), outcomeTone(result))
                    onLaunched()
                  })
                  .catch((error: unknown) => {
                    say(failureMessage(error), 'danger')
                    onLaunched()
                  })
              }}
            >
              {profile.label}
              {profile.user_defined ? <span className="faint small"> · yours</span> : null}
            </CommitButton>
          )
        })}
      </div>
      {stale ? (
        <p className="small warning-text" data-testid="launch-stale">
          {connected
            ? 'The prompt changed since these were drawn. Nothing will be typed into it.'
            : 'Not in contact with this host, so nothing can be started on it.'}
          {connected ? (
            <Button
              data-testid="launch-refresh"
              onClick={() => {
                setDrawnAt(promptGeneration)
              }}
            >
              I have looked at the prompt
            </Button>
          ) : null}
        </p>
      ) : (
        <p className="small faint">
          The prompt is empty and verified. A launch installs the command; it never pastes one.
        </p>
      )}
    </section>
  )
}

/** The composer. */
function Composer({
  draft,
  connected,
  offers,
  commands,
  insertion,
  onChange,
  onAction
}: {
  readonly draft: Draft
  readonly connected: boolean
  readonly offers: ComposerOffers
  readonly commands: readonly AgentCommand[]
  readonly insertion: string | null
  readonly onChange: (text: string) => void
  readonly onAction: (action: ComposerAction) => void
}): ReactNode {
  const [showCommands, setShowCommands] = useState(false)
  const typed = draft.text.startsWith('/') ? draft.text.slice(1).toLowerCase() : null
  const offered =
    typed === null ? [] : commands.filter((command) => command.name.toLowerCase().startsWith(typed))
  const reason = offers.submit.offered ? notSubmittableBecause(draft) : offers.submit.reason
  const canSubmit = offers.submit.offered && submittable(draft) && connected
  const canWrite = submittable(draft) && connected

  return (
    <div className="composer" data-testid="composer" data-draft-state={draft.state}>
      {insertion ? (
        <p className="banner warning" data-testid="insertion-refusal">
          {insertion}
        </p>
      ) : null}

      {draft.attachments.length > 0 ? (
        <div className="row wrap">
          {draft.attachments.map((attachment) => (
            <span className="attachment-chip" key={attachment.transferId}>
              {attachment.name}
              {attachment.acceptedUpstream ? (
                <Badge tone="success">Accepted</Badge>
              ) : (
                <Badge tone="neutral">Uploaded</Badge>
              )}
            </span>
          ))}
        </div>
      ) : null}

      <label>
        <span className="visually-hidden">Message</span>
        <textarea
          value={draft.text}
          data-testid="composer-input"
          placeholder={
            commands.length > 0 ? 'Ask for something, or press / for a command' : 'Ask for something'
          }
          onChange={(event) => {
            onChange(event.target.value)
            setShowCommands(event.target.value.startsWith('/'))
          }}
          onKeyDown={(event) => {
            if (event.key === 'Enter' && (event.metaKey || event.ctrlKey)) {
              event.preventDefault()
              if (canSubmit) onAction('submit')
            }
          }}
        />
      </label>

      {showCommands && offered.length > 0 ? (
        <ul className="slash-commands" data-testid="slash-commands">
          {offered.map((command) => (
            <li key={command.name}>
              <button
                type="button"
                className="text-link"
                onClick={() => {
                  onChange(`/${command.name} `)
                  setShowCommands(false)
                }}
              >
                <code>/{command.name}</code>
                <span className="faint">{command.summary}</span>
              </button>
            </li>
          ))}
        </ul>
      ) : null}

      <div className="composer-note between">
        <span className="faint small" data-testid="composer-reason">
          {reason ?? 'Command-Enter sends it.'}
        </span>
        <span className="row">
          {offers.interrupt.offered ? (
            <IconButton
              label="Interrupt the current turn"
              data-testid="composer-interrupt"
              disabled={!connected}
              onClick={() => {
                onAction('interrupt')
              }}
            >
              &#9632;
            </IconButton>
          ) : null}
          {offers.steer.offered ? (
            <Button
              data-testid="composer-steer"
              disabled={!canWrite}
              onClick={() => {
                onAction('steer')
              }}
            >
              Steer
            </Button>
          ) : null}
          {offers.queue.offered ? (
            <Button
              data-testid="composer-queue"
              disabled={!canWrite}
              onClick={() => {
                onAction('queue')
              }}
            >
              Queue
            </Button>
          ) : null}
          <Button
            tone="primary"
            data-testid="composer-send"
            disabled={!canSubmit}
            onClick={() => {
              onAction('submit')
            }}
          >
            Send
          </Button>
        </span>
      </div>
    </div>
  )
}
