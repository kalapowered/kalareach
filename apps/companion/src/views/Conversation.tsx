/**
 * The semantic view: the document, and the composer under it.
 *
 * The document is the portable node union. Every node has a stable identity and a revision, the
 * rendered set is bounded, and a node kind this client does not draw renders an unsupported block
 * that can invoke nothing.
 *
 * Streamed output does not animate. Text that fades in each time a token arrives reads as lag, and
 * this is the surface a person watches most.
 */

import { memo, useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react'

import type { DocumentNode } from '@kalareach/plugin-sdk'

import { Badge, Button, Card, CommitButton, IconButton } from '../components/ui'
import { ENVIRONMENT_ID, useApp } from '../app/state'
import { failureCode, failureMessage, type DroppedFile } from '../host/port'
import { renderMarkdown } from '../markdown/render'
import {
  applyNodes,
  emptyConversation,
  nodesAbove,
  prependHistory,
  setFollowing,
  visibleNodes,
  type ConversationState
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
  startDraft,
  submittable,
  type Draft
} from '../model/drafts'
import { FrameBatcher } from '../model/frame'
import {
  failed,
  queued,
  reconnectBanner,
  sent,
  settled,
  describeState,
  type Submission
} from '../model/receipts'
import type { LaunchSurface } from '../model/pending'
import { Banner } from '../components/ui'

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

/** The composer's own actions, which the specification names. */
type ComposerAction = 'submit' | 'queue' | 'steer' | 'interrupt'

/** The semantic view of one session. */
export function Conversation({
  sessionId,
  connected,
  launch,
  onLaunched
}: {
  readonly sessionId: string
  readonly connected: boolean
  readonly launch: LaunchSurface | null
  readonly onLaunched: () => void
}): ReactNode {
  const { port, say } = useApp()
  const [state, setState] = useState<ConversationState>(emptyConversation)
  const [submissions, setSubmissions] = useState<readonly Submission[]>([])
  const [draft, setDraft] = useState<Draft>(() =>
    startDraft(`d-${sessionId}`, { sessionId, applicationInstanceId: null, agentBindingRevision: null }, Date.now())
  )
  const [images, setImages] = useState<ReadonlyMap<string, string>>(new Map())
  const [insertion, setInsertion] = useState<string | null>(null)
  const [frames, setFrames] = useState(0)
  const scroller = useRef<HTMLDivElement | null>(null)

  // One batch per animation frame. Forty events in one tick are one render, and the composer keeps
  // taking keystrokes while they arrive.
  const batcher = useMemo(
    () =>
      new FrameBatcher<DocumentNode>((batch) => {
        setState((current) => applyNodes(current, batch))
        setFrames((count) => count + 1)
      }),
    []
  )

  useEffect(() => {
    let cancelled = false
    port
      .agentSnapshot(ENVIRONMENT_ID, { session_id: sessionId })
      .then((snapshot) => {
        if (!cancelled) setState((current) => applyNodes(current, snapshot.nodes))
      })
      .catch(() => {
        // A snapshot that cannot be read leaves the view empty and the banner says why.
      })
    return () => {
      cancelled = true
      batcher.discard()
    }
  }, [port, sessionId, batcher])

  useEffect(() => {
    const stop = port.subscribe((event) => {
      const body = event.body as { kind?: string; node?: DocumentNode; receipt?: unknown }
      if (body.kind === 'node' && body.node) batcher.push(body.node)
      if (body.kind === 'receipt' && body.receipt) {
        const receipt = body.receipt as { action_id: string }
        setSubmissions((current) =>
          current.map((submission) =>
            submission.actionId === receipt.action_id
              ? settled(submission, body.receipt as Parameters<typeof settled>[1])
              : submission
          )
        )
      }
    })
    return stop
  }, [port, batcher])

  // Losing contact removes the association, not the draft. That is a fact about the connection, so
  // it is derived here rather than written into the stored draft: the text, the revision and the
  // attachments are untouched, and a rebind is still the explicit act it has to be.
  const presented = useMemo(
    () => (connected ? draft : connectionLost(draft)),
    [connected, draft]
  )

  const controlState: ControlState = useMemo(() => {
    const present = new Set(state.nodes.map((node) => node.id))
    return { ...emptyControlState(), presentNodes: present }
  }, [state.nodes])

  const send = useCallback(
    (action: ComposerAction) => {
      const label = draft.text.trim() || action
      const local = queued(`s-${Date.now()}-${Math.random()}`, label, Date.now())
      setSubmissions((current) => [...current, local])
      // Local feedback first: the composer clears and the entry appears as queued. The completion
      // feedback below waits for the receipt.
      if (action === 'submit' || action === 'queue') {
        setDraft((current) => edit(current, '', Date.now()))
      }
      const params = { session_id: sessionId, text: draft.text }
      const call =
        action === 'submit'
          ? port.composerSubmit(ENVIRONMENT_ID, params)
          : action === 'queue'
            ? port.composerQueue(ENVIRONMENT_ID, params)
            : action === 'steer'
              ? port.composerSteer(ENVIRONMENT_ID, params)
              : port.composerInterrupt(ENVIRONMENT_ID, { session_id: sessionId })

      call
        .then((result) => {
          setSubmissions((current) =>
            current.map((submission) => {
              if (submission.localId !== local.localId) return submission
              const withAction = result.receipt
                ? sent(submission, result.receipt.action_id)
                : submission
              return result.receipt ? settled(withAction, result.receipt) : withAction
            })
          )
        })
        .catch((error: unknown) => {
          setSubmissions((current) =>
            current.map((submission) =>
              submission.localId === local.localId
                ? failed(submission, {
                    code: failureCode(error) ?? 'UNKNOWN',
                    message: failureMessage(error)
                  })
                : submission
            )
          )
          say(failureMessage(error), 'danger')
        })
    },
    [draft.text, port, sessionId, say]
  )

  const attach = useCallback(
    (files: readonly DroppedFile[]) => {
      for (const file of files) {
        port
          .draftAddAttachment(ENVIRONMENT_ID, {
            session_id: sessionId,
            draft_id: draft.draftId,
            original_file_name: file.name,
            insertion_method: 'typed_submission'
          })
          .then(() => {
            say(`${file.name} attached.`)
          })
          .catch((error: unknown) => {
            const refusal = readInsertionRefusal(failureCode(error) ?? 'UNKNOWN')
            setInsertion(refusal.fallback)
          })
      }
    },
    [draft.draftId, port, sessionId, say]
  )

  useEffect(() => port.onFilesDropped(attach), [port, attach])

  const banner = reconnectBanner(connected, submissions)
  // The window's identity changes only when the document does, so a keystroke in the composer
  // cannot make the memoised document below re-render.
  const rendered = useMemo(() => visibleNodes(state), [state])
  const hidden = nodesAbove(state)

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
          setImages((current) => new Map(current).set(url, URL.createObjectURL(blob)))
        })
        .catch((error: unknown) => {
          say(failureMessage(error), 'danger')
        })
    },
    [port, say]
  )

  const invoke = useCallback(
    (control: Control) => {
      port
        .pluginActionInvoke(ENVIRONMENT_ID, {
          session_id: sessionId,
          action_id: control.action_id,
          control_revision: control.revision
        })
        .then(() => {
          say(`${control.label} done.`)
        })
        .catch((error: unknown) => {
          say(failureMessage(error), 'danger')
        })
    },
    [port, sessionId, say]
  )

  const loadOlder = () => {
    port
      .historyPage(ENVIRONMENT_ID, { session_id: sessionId })
      .then(() => {
        // The anchor is kept by the model: the window start moves by exactly what was prepended.
        setState((current) => prependHistory(current, []))
      })
      .catch(() => {
        say('Older history could not be read.', 'danger')
      })
  }

  return (
    <div className="conversation" data-testid="conversation" data-frames={frames}>
      {banner ? <Banner tone={banner.tone} title={banner.title} detail={banner.detail} /> : null}

      {submissions.length > 0 ? (
        <ul className="pending-actions" data-testid="pending-actions">
          {submissions.map((submission) => (
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

      <div className="conversation-scroll" ref={scroller} data-testid="conversation-scroll">
        {hidden > 0 ? (
          <div className="history-edge">
            <Button onClick={loadOlder}>Load {hidden} earlier</Button>
          </div>
        ) : null}

        <Document
          nodes={rendered}
          controlState={controlState}
          images={images}
          onOpenLink={openLink}
          onImportImage={importImage}
          onInvoke={invoke}
        />
      </div>

      {launch && launch.prompt_is_empty ? (
        <LaunchSurfaceView
          surface={launch}
          sessionId={sessionId}
          onLaunched={onLaunched}
        />
      ) : null}

      <Composer
        draft={presented}
        connected={connected}
        insertion={insertion}
        onChange={(text) => {
          setDraft((current) => edit(current, text, Date.now()))
        }}
        onAction={send}
        onFollowChange={(following) => {
          setState((current) => setFollowing(current, following))
        }}
      />
    </div>
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
  sessionId,
  onLaunched
}: {
  readonly surface: LaunchSurface
  readonly sessionId: string
  readonly onLaunched: () => void
}): ReactNode {
  const { port, say } = useApp()
  const [drawnAt] = useState(surface.prompt_generation)
  const stale = drawnAt !== surface.prompt_generation

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
                  .shellLaunch(ENVIRONMENT_ID, {
                    session_id: sessionId,
                    command: { arguments: [...profile.arguments] },
                    expected_prompt_generation: surface.prompt_generation,
                    expected_buffer_revision: surface.buffer_revision
                  })
                  .then(() => {
                    say(`${profile.label} started.`)
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
          The prompt changed since these were drawn. Nothing will be typed into it.
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
  insertion,
  onChange,
  onAction,
  onFollowChange
}: {
  readonly draft: Draft
  readonly connected: boolean
  readonly insertion: string | null
  readonly onChange: (text: string) => void
  readonly onAction: (action: ComposerAction) => void
  readonly onFollowChange: (following: boolean) => void
}): ReactNode {
  const [showCommands, setShowCommands] = useState(false)
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
          onFocus={() => {
            onFollowChange(true)
          }}
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

      {showCommands ? (
        <ul className="slash-commands" data-testid="slash-commands">
          <li>
            <code>/compact</code> <span className="faint">Shorten the conversation so far</span>
          </li>
          <li>
            <code>/model</code> <span className="faint">Change the model for this session</span>
          </li>
          <li>
            <code>/review</code> <span className="faint">Review the current change set</span>
          </li>
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
