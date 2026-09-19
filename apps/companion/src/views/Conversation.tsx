/**
 * The semantic view: the document, and the composer under it.
 *
 * The document is the portable node union. Every node has a stable identity and a revision, the
 * rendered set is bounded, and a node kind this client does not draw renders an unsupported block
 * that can invoke nothing.
 *
 * Nothing in this component owns the session's state. The draft, the document, the window and the
 * pending actions live in the application's per-session store, so switching to the terminal and
 * back keeps them, and one session's state can never appear under another's name.
 *
 * Streamed output does not animate. Text that fades in each time a token arrives reads as lag, and
 * this is the surface a person watches most.
 */

import { memo, useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react'

import type { DocumentNode } from '@kalareach/plugin-sdk'

import { Badge, Banner, Button, Card, CommitButton, IconButton } from '../components/ui'
import { useApp, useSession } from '../app/state'
import {
  failureCode,
  failureMessage,
  type DroppedFile,
  type SessionSubject
} from '../host/port'
import { renderMarkdown } from '../markdown/render'
import {
  applyNodes,
  nodesAbove,
  prependHistory,
  setFollowing,
  setWindowStart,
  visibleNodes,
  WINDOW_SIZE
} from '../model/conversation'
import {
  emptyControlState,
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
  describeState,
  failed,
  queued,
  reconnectBanner,
  sent,
  settled
} from '../model/receipts'
import type { LaunchSurface } from '../model/pending'

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
  launch,
  onLaunched
}: {
  readonly sessionId: string
  readonly subject: SessionSubject
  readonly connected: boolean
  readonly launch: LaunchSurface | null
  readonly onLaunched: () => void
}): ReactNode {
  const { port, say } = useApp()
  const { state, update } = useSession(sessionId)
  const [insertion, setInsertion] = useState<string | null>(null)
  const [commands, setCommands] = useState<readonly AgentCommand[]>([])
  const scroller = useRef<HTMLDivElement | null>(null)

  // One batch per animation frame. Forty events in one tick are one render, and the composer keeps
  // taking keystrokes while they arrive.
  const batcher = useMemo(
    () =>
      new FrameBatcher<DocumentNode>((batch) => {
        update((current) => ({
          ...current,
          conversation: applyNodes(current.conversation, batch)
        }))
      }),
    [update]
  )

  useEffect(() => {
    let cancelled = false
    port
      .agentSnapshot({ session_id: sessionId })
      .then((snapshot) => {
        if (cancelled) return
        update((current) => ({
          ...current,
          conversation: applyNodes(current.conversation, snapshot.nodes),
          loaded: true
        }))
      })
      .catch(() => {
        // A snapshot that cannot be read leaves the view as it was, and the banner says why.
      })
    return () => {
      cancelled = true
      batcher.discard()
    }
  }, [port, sessionId, batcher, update])

  useEffect(() => {
    let cancelled = false
    port
      .agentCommands({ session_id: sessionId })
      .then((answer) => {
        if (!cancelled) setCommands(readAgentCommands(answer))
      })
      .catch(() => {
        // An agent whose commands this client cannot read offers none, rather than offering a
        // list written here that the agent may not have.
        if (!cancelled) setCommands([])
      })
    return () => {
      cancelled = true
    }
  }, [port, sessionId])

  useEffect(() => {
    const stop = port.subscribe((event) => {
      const body = event.body as { kind?: string; node?: DocumentNode; receipt?: unknown }
      // An event belongs to the stream it names. A view showing one session ignores another's
      // rather than folding it into what the person is looking at.
      if (body.kind === 'node' && body.node && eventIsFor(event.stream_id, sessionId)) {
        batcher.push(body.node)
      }
      if (body.kind === 'receipt' && body.receipt) {
        const receipt = body.receipt as { action_id: string }
        update((current) => ({
          ...current,
          submissions: current.submissions.map((submission) =>
            submission.actionId === receipt.action_id
              ? settled(submission, body.receipt as Parameters<typeof settled>[1])
              : submission
          )
        }))
      }
    })
    return stop
  }, [port, batcher, sessionId, update])

  const controlState: ControlState = useMemo(() => {
    const present = new Set(state.conversation.nodes.map((node) => node.id))
    return { ...emptyControlState(), presentNodes: present }
  }, [state.conversation.nodes])

  const send = useCallback(
    (action: ComposerAction) => {
      const typed = state.draft.text
      const label = typed.trim() || action
      const local = queued(`s-${Date.now()}-${Math.random()}`, label, Date.now())
      const clears = action === 'submit' || action === 'queue'

      // Local feedback first: the entry appears as queued and the composer clears. The completion
      // feedback below waits for the receipt.
      update((current) => ({
        ...current,
        submissions: [...current.submissions, local],
        draft: clears ? edit(current.draft, '', Date.now()) : current.draft
      }))

      const params = { session_id: sessionId, text: typed }
      const call =
        action === 'submit'
          ? port.composerSubmit(params, subject)
          : action === 'queue'
            ? port.composerQueue(params, subject)
            : action === 'steer'
              ? port.composerSteer(params, subject)
              : port.composerInterrupt({ session_id: sessionId }, subject)

      call
        .then((result) => {
          update((current) => ({
            ...current,
            submissions: current.submissions.map((submission) => {
              if (submission.localId !== local.localId) return submission
              const identified = result.action_id
                ? sent(submission, result.action_id)
                : submission
              return result.receipt ? settled(identified, result.receipt) : identified
            })
          }))
        })
        .catch((error: unknown) => {
          const code = failureCode(error) ?? 'UNKNOWN'
          update((current) => ({
            ...current,
            submissions: current.submissions.map((submission) =>
              submission.localId === local.localId
                ? failed(submission, { code, message: failureMessage(error) })
                : submission
            ),
            // A refused submission gives the text back. Losing what someone wrote because the host
            // said no is the one outcome a composer must never have.
            draft:
              clears && current.draft.text.length === 0
                ? edit(current.draft, typed, Date.now())
                : current.draft
          }))
          say(failureMessage(error), 'danger')
        })
    },
    [port, sessionId, subject, state.draft.text, update, say]
  )

  const attach = useCallback(
    (files: readonly DroppedFile[]) => {
      for (const file of files) {
        port
          .draftAddAttachment(
            {
              draft_id: state.draft.draftId,
              original_file_name: file.name,
              insertion_method: 'typed_submission'
            },
            subject
          )
          .then((result) => {
            // Only an applied receipt says the attachment reached the draft.
            if (result.receipt?.state === 'applied') say(`${file.name} attached.`)
            else say(`${file.name} sent. Waiting for the host to confirm.`)
          })
          .catch((error: unknown) => {
            const refusal = readInsertionRefusal(failureCode(error) ?? 'UNKNOWN')
            setInsertion(refusal.fallback)
          })
      }
    },
    [port, state.draft.draftId, subject, say]
  )

  useEffect(() => port.onFilesDropped(attach), [port, attach])

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
          say(
            result.receipt?.state === 'applied'
              ? `${control.label} done.`
              : `${control.label} sent. Waiting for the host to confirm.`
          )
        })
        .catch((error: unknown) => {
          say(failureMessage(error), 'danger')
        })
    },
    [port, subject, say]
  )

  /**
   * Loads the page of history above what is held, and keeps the reader where they are.
   *
   * The window moves by exactly the number of nodes that were added, so the node the person was
   * looking at stays in the same place.
   */
  const loadOlder = useCallback(() => {
    port
      .historyPage({ session_id: sessionId })
      .then((page) => {
        const older = readHistoryNodes(page)
        if (older.length === 0) {
          say('There is no more history on this host.')
          return
        }
        update((current) => ({
          ...current,
          conversation: prependHistory(current.conversation, older)
        }))
      })
      .catch((error: unknown) => {
        say(failureMessage(error), 'danger')
      })
  }, [port, sessionId, update, say])

  /**
   * Moves the window and decides whether the view is still following.
   *
   * Following is what the scroll position says, not a setting: a person who has scrolled up is
   * reading, and new output must not pull them away from it.
   */
  const onScroll = useCallback(() => {
    const element = scroller.current
    if (!element) return
    const atEnd = element.scrollHeight - element.scrollTop - element.clientHeight < 32
    const total = state.conversation.nodes.length
    const fraction =
      element.scrollHeight <= element.clientHeight
        ? 0
        : element.scrollTop / (element.scrollHeight - element.clientHeight)
    const start = Math.round(fraction * Math.max(0, total - WINDOW_SIZE))
    update((current) => ({
      ...current,
      conversation: atEnd
        ? setFollowing(current.conversation, true)
        : setWindowStart(current.conversation, start)
    }))
  }, [state.conversation.nodes.length, update])

  return (
    <div className="conversation" data-testid="conversation">
      {banner ? <Banner tone={banner.tone} title={banner.title} detail={banner.detail} /> : null}

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
      >
        {hidden > 0 ? (
          <div className="history-edge">
            <Button data-testid="load-older" onClick={loadOlder}>
              Load earlier output
            </Button>
          </div>
        ) : null}

        <Document
          nodes={rendered}
          controlState={controlState}
          images={state.images}
          onOpenLink={openLink}
          onImportImage={importImage}
          onInvoke={invoke}
        />
      </div>

      {launch?.prompt_is_empty ? (
        <LaunchSurfaceView
          surface={launch}
          subject={subject}
          sessionId={sessionId}
          connected={connected}
          onLaunched={onLaunched}
        />
      ) : null}

      <Composer
        draft={presented}
        connected={connected}
        commands={commands}
        insertion={insertion}
        onChange={(next) => {
          update((current) => ({ ...current, draft: edit(current.draft, next, Date.now()) }))
        }}
        onAction={send}
      />
    </div>
  )
}

/** One command the bound agent supports. */
export interface AgentCommand {
  readonly name: string
  readonly summary: string
}

/** The commands in what `agent.commands` answered, and nothing this client invented. */
function readAgentCommands(answer: unknown): readonly AgentCommand[] {
  if (typeof answer !== 'object' || answer === null) return []
  const commands = (answer as { commands?: unknown }).commands
  if (!Array.isArray(commands)) return []
  return commands
    .filter((command): command is Record<string, unknown> => typeof command === 'object' && command !== null)
    .map((command) => ({ name: text(command.name), summary: text(command.summary) }))
    .filter((command) => command.name.length > 0)
}

/**
 * The nodes in one page of retained history.
 *
 * A host that answered with something this client cannot read contributes nothing rather than
 * contributing a guess.
 */
function readHistoryNodes(page: unknown): readonly DocumentNode[] {
  if (typeof page !== 'object' || page === null) return []
  const nodes = (page as { nodes?: unknown }).nodes
  if (!Array.isArray(nodes)) return []
  return nodes.filter(
    (node): node is DocumentNode =>
      typeof node === 'object' &&
      node !== null &&
      typeof (node as DocumentNode).id === 'string' &&
      typeof (node as DocumentNode).revision === 'string'
  )
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
  nodes,
  controlState,
  images,
  onOpenLink,
  onImportImage,
  onInvoke
}: {
  readonly nodes: readonly DocumentNode[]
  readonly controlState: ControlState
  readonly images: ReadonlyMap<string, string>
  readonly onOpenLink: (url: string) => void
  readonly onImportImage: (url: string) => void
  readonly onInvoke: (control: Control) => void
}): ReactNode {
  return (
    <>
      {nodes.map((node) => (
        <NodeView
          key={node.id}
          node={node}
          controlState={controlState}
          images={images}
          onOpenLink={onOpenLink}
          onImportImage={onImportImage}
          onInvoke={onInvoke}
        />
      ))}
    </>
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
    typeof fields === 'object' && fields !== null && Array.isArray((fields as { fields?: unknown }).fields)
      ? ((fields as { fields: unknown[] }).fields as Record<string, unknown>[])
      : []
  if (entries.length === 0) return null
  return (
    <div data-testid="form-fields">
      {entries.map((field, index) => {
        const name = text(field.name) || `field-${index}`
        const label = text(field.label) || name
        const kind = text(field.kind) || text(field.type)
        return (
          <label className="form-field" key={name}>
            <span>{label}</span>
            {kind === 'boolean' ? (
              <input type="checkbox" name={name} />
            ) : kind === 'number' || kind === 'integer' ? (
              <input type="number" name={name} />
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
  subject,
  sessionId,
  connected,
  onLaunched
}: {
  readonly surface: LaunchSurface
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
  const stale = drawnAt !== surface.prompt_generation || !connected

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
                      expected_prompt_generation: surface.prompt_generation,
                      expected_buffer_revision: surface.buffer_revision
                    },
                    subject
                  )
                  .then((result) => {
                    say(
                      result.receipt?.state === 'applied'
                        ? `${profile.label} started.`
                        : `${profile.label} requested. Waiting for the host to confirm.`
                    )
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
                setDrawnAt(surface.prompt_generation)
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
  commands,
  insertion,
  onChange,
  onAction
}: {
  readonly draft: Draft
  readonly connected: boolean
  readonly commands: readonly AgentCommand[]
  readonly insertion: string | null
  readonly onChange: (text: string) => void
  readonly onAction: (action: ComposerAction) => void
}): ReactNode {
  const [showCommands, setShowCommands] = useState(false)
  const typed = draft.text.startsWith('/') ? draft.text.slice(1).toLowerCase() : null
  const offered =
    typed === null ? [] : commands.filter((command) => command.name.slice(1).startsWith(typed))
  const reason = notSubmittableBecause(draft)
  const canSubmit = submittable(draft) && connected

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
          placeholder="Ask for something, or press / for a command"
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
                  onChange(`${command.name} `)
                  setShowCommands(false)
                }}
              >
                <code>{command.name}</code>
                <span className="faint">{command.summary}</span>
              </button>
            </li>
          ))}
        </ul>
      ) : null}

      <div className="composer-note between">
        <span className="faint small">{reason ?? 'Command-Enter sends it.'}</span>
        <span className="row">
          <IconButton
            label="Interrupt the current turn"
            data-testid="composer-interrupt"
            onClick={() => {
              onAction('interrupt')
            }}
          >
            &#9632;
          </IconButton>
          <Button
            data-testid="composer-steer"
            disabled={!canSubmit}
            onClick={() => {
              onAction('steer')
            }}
          >
            Steer
          </Button>
          <Button
            data-testid="composer-queue"
            disabled={!canSubmit}
            onClick={() => {
              onAction('queue')
            }}
          >
            Queue
          </Button>
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
