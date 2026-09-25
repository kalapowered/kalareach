/**
 * One session, in whichever view the person is using.
 *
 * The two views share a session, a draft and a position. Switching between them is a switch of
 * presentation, not of place: the composer keeps what was typed and the raw view keeps where it was
 * looking. Settings open over this screen rather than replacing it, because a person adjusting a
 * setting is still in the session.
 */

import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react'

import type { SessionReadResult } from '@kalareach/protocol'

import { Badge, Banner, Button, Card, CommitButton, Segmented, Sheet, Switch, ThemeChooser } from '../components/ui'
import { useApp } from '../app/state'
import { failureMessage, watch, type HostPort, type SessionSubject, type Watch } from '../host/port'
import type { LaunchSurface } from '../model/pending'
import { Conversation, outcomeMessage, receiptTone } from './Conversation'
import { RawTerminal } from '../terminal/RawTerminal'
import { terminalAttachment } from '../terminal/modes'
import { ask } from '../mobile/model/call'
import { describeApplicationState, sessionDescription } from './Sessions'

/** What the view has read of one session. */
interface SessionReading {
  readonly sessionId: string
  readonly session: SessionReadResult
}

/**
 * A launch surface one watch read, and the prompt's generation as that watch knows it: the one
 * the surface was read at, or one heard since.
 *
 * It belongs to that watch. It is offered only for the port, session and attempt the watch was
 * started for, and it is gone once the watch ends, so the only surface ever offered is one read
 * while the listeners that follow its prompt are registered.
 */
interface Launch {
  readonly watch: Watch
  readonly port: HostPort
  readonly sessionId: string
  readonly attempt: number
  readonly surface: LaunchSurface
  readonly promptGeneration: string
}

/** `launch` with nothing from `watch` in it. */
function without(launch: Launch | null, watch: Watch): Launch | null {
  return launch?.watch === watch ? null : launch
}

/** The view of one session. */
export function Session({
  sessionId,
  pane
}: {
  readonly sessionId: string
  readonly pane: 'semantic' | 'terminal'
}): ReactNode {
  const { port, go, say, tabs, closeTab } = useApp()
  const [reading, setReading] = useState<SessionReading | null>(null)
  const [launch, setLaunch] = useState<Launch | null>(null)
  const [connected, setConnected] = useState(true)
  const [settingsOpen, setSettingsOpen] = useState(false)
  const [closing, setClosing] = useState(false)
  // "Try again" registers the listeners again, and reads only once they are.
  const [attempt, setAttempt] = useState(0)
  // The load of the watch that is listening now, for a launch that asks the view to read again.
  const reload = useRef<(() => void) | null>(null)

  // The session and its launch surface are read once the listeners are registered, and only
  // within that watch: a read it did not start, or an answer after it ended, is never shown.
  useEffect(() => {
    // The changes heard in this watch, counted, so a read can tell whether one overtook it, and
    // the prompt generation it heard last.
    let connectionChanges = 0
    let generationChanges = 0
    let heardGeneration: string | null = null
    let watching: Watch | null = null
    const load = () => {
      const current = watching?.read() ?? null
      if (current === null) return
      const connectionAt = connectionChanges
      const generationAt = generationChanges
      ask(() => port.sessionRead({ session_id: sessionId }))
        .then((result) => {
          if (!current()) return
          setReading({ sessionId, session: result })
          // An answer says the host was reached when it was read; a change heard since is newer.
          if (connectionChanges === connectionAt) setConnected(true)
        })
        .catch(() => {
          if (current() && connectionChanges === connectionAt) setConnected(false)
        })
      ask(() => port.launchSurface({ session_id: sessionId }))
        .then((surface) => {
          if (!current() || watching === null) return
          // A generation heard since this read was made is the prompt's, and the buttons drawn
          // from the read stay disabled until the person has looked at the prompt again.
          const overtaken = generationChanges !== generationAt
          setLaunch({
            watch: watching,
            port,
            sessionId,
            attempt,
            surface,
            promptGeneration: overtaken
              ? (heardGeneration ?? surface.prompt_generation)
              : surface.prompt_generation
          })
        })
        .catch(() => {
          // Without a verified empty prompt there is no launch surface, which is the right answer
          // rather than a set of buttons drawn hopefully.
          if (!current() || watching === null) return
          const ended = watching
          setLaunch((shown) => without(shown, ended))
        })
    }
    watching = watch(
      [
        port.onConnection((state) => {
          connectionChanges += 1
          setConnected(state.connected)
        }),
        port.subscribe((event) => {
          const body = event.body as { kind?: string; prompt_generation?: string }
          if (body.kind !== 'prompt_generation' || !body.prompt_generation) return
          // The launch surface is only valid at the generation it was read at. A generation that
          // moved disables the buttons rather than silently launching against the new prompt.
          const generation = body.prompt_generation
          generationChanges += 1
          heardGeneration = generation
          const hearing = watching
          setLaunch((shown) =>
            shown !== null && shown.watch === hearing
              ? { ...shown, promptGeneration: generation }
              : shown
          )
        })
      ],
      () => {
        reload.current = load
        load()
      },
      () => {
        // A view that cannot follow the host says so and offers no launch. Its banner's "Try
        // again" registers the listeners again before it reads.
        const failed = watching
        if (failed !== null) setLaunch((shown) => without(shown, failed))
        setConnected(false)
      }
    )
    const started = watching
    return () => {
      started.stop()
      setLaunch((shown) => without(shown, started))
      if (reload.current === load) reload.current = null
    }
  }, [port, sessionId, attempt])

  const readAgain = useCallback(() => {
    reload.current?.()
  }, [])

  const session = reading?.sessionId === sessionId ? reading.session : null
  const offered =
    launch !== null &&
    launch.port === port &&
    launch.sessionId === sessionId &&
    launch.attempt === attempt
      ? launch
      : null

  const summary = session?.session
  const state = summary ? describeApplicationState(summary) : null
  // What every mutation about this session names. The epoch comes from the host's own record of
  // the session, beside its identifier, so an action can never be aimed at a session that has been
  // replaced since the person looked at it.
  const subject: SessionSubject = summary
    ? { sessionId: summary.session_id, sessionEpoch: summary.session_epoch }
    : {}

  return (
    <>
      {tabs.length > 1 ? (
        <div className="session-tabs" role="tablist" aria-label="Open sessions" data-testid="session-tabs">
          {tabs.map((tab) => (
            <span className="session-tab" key={tab} data-active={tab === sessionId}>
              <button
                type="button"
                role="tab"
                aria-selected={tab === sessionId}
                onClick={() => {
                  go({ view: 'session', sessionId: tab, pane })
                }}
              >
                Session {tab.slice(-2)}
              </button>
              <button
                type="button"
                aria-label={`Close the tab for session ${tab.slice(-2)}`}
                onClick={() => {
                  closeTab(tab)
                  if (tab === sessionId) go({ view: 'sessions' })
                }}
              >
                ×
              </button>
            </span>
          ))}
        </div>
      ) : null}

      <header className="page-heading session-header">
        <div>
          <p className="eyebrow">
            Session {summary?.display_number ?? ''}
            {state ? ` · ${state.label}` : ''}
          </p>
          <h1>{summary ? sessionDescription(summary) : 'Session'}</h1>
          <p className="session-meta mono">{summary?.cwd ?? ''}</p>
        </div>
        <div className="page-actions">
          <Segmented
            label="View"
            value={pane}
            options={[
              { value: 'semantic', label: 'Conversation' },
              { value: 'terminal', label: 'Terminal' }
            ]}
            onChange={(next) => {
              go({ view: 'session', sessionId, pane: next })
            }}
          />
          <span className="session-commands">
            <Button
              data-testid="open-settings"
              onClick={() => {
                setSettingsOpen(true)
              }}
            >
              Settings
            </Button>
            <Button
              tone="danger"
              data-testid="close-session"
              onClick={() => {
                setClosing(true)
              }}
            >
              Close session
            </Button>
          </span>
        </div>
      </header>

      {!connected ? (
        <Banner
          tone="warning"
          title="Not in contact with this host"
          detail="This session may still be running. Nothing here says otherwise."
          action={
            <Button
              onClick={() => {
                setAttempt((count) => count + 1)
              }}
            >
              Try again
            </Button>
          }
        />
      ) : null}

      {pane === 'semantic' ? (
        <Conversation
          sessionId={sessionId}
          subject={subject}
          connected={connected}
          launch={
            offered
              ? { surface: offered.surface, promptGeneration: offered.promptGeneration }
              : null
          }
          onLaunched={readAgain}
        />
      ) : (
        <RawTerminal
          sessionId={sessionId}
          subject={subject}
          attachmentId={terminalAttachment(sessionId)}
          onReleaseGeometry={() => {
            go({ view: 'session', sessionId, pane: 'semantic' })
          }}
        />
      )}

      <SessionSettings
        open={settingsOpen}
        sessionId={sessionId}
        subject={subject}
        onClose={() => {
          setSettingsOpen(false)
        }}
      />

      <CloseConsequence
        open={closing}
        session={summary ?? null}
        onCancel={() => {
          setClosing(false)
        }}
        onConfirm={() => {
          port
            .sessionClose({ session_id: sessionId }, subject)
            .then((result) => {
              setClosing(false)
              say(
                outcomeMessage('The session is closed, and its history is kept', result.receipt),
                receiptTone(result.receipt)
              )
              if (result.receipt?.state === 'applied') go({ view: 'sessions' })
            })
            .catch((error: unknown) => {
              setClosing(false)
              say(failureMessage(error), 'danger')
            })
        }}
      />
    </>
  )
}

/**
 * What closing does, shown before the person commits to it.
 *
 * Section 7 is specific about what close means and what it does not: it invalidates pending
 * approvals and stops supervised backends, and it does not delete retained history. Both sentences
 * belong in front of the person, because "close" reads like "delete" to most people and it is not.
 */
function CloseConsequence({
  open,
  session,
  onCancel,
  onConfirm
}: {
  readonly open: boolean
  readonly session: SessionReadResult['session'] | null
  readonly onCancel: () => void
  readonly onConfirm: () => void
}): ReactNode {
  return (
    <Sheet
      open={open}
      title="Close this session?"
      description="This is what closing does."
      onClose={onCancel}
      footer={
        <>
          <Button onClick={onCancel}>Keep it open</Button>
          <CommitButton tone="danger" data-testid="confirm-close" onCommit={onConfirm}>
            Close the session
          </CommitButton>
        </>
      }
    >
      <ul className="consequence-list" data-testid="close-consequence">
        <li>
          The root shell stops, and every process it owns is asked to finish. Anything still running
          after five seconds is ended.
        </li>
        <li>Approvals that are waiting are invalidated. Nothing pending is answered for you.</li>
        <li>
          {session ? `${session.attachment_count} attached ` : 'Attached '}
          {session?.attachment_count === '1' ? 'view stops' : 'views stop'} following it.
        </li>
        <li>
          <strong>Retained history is kept.</strong> Closing is not deleting: the conversation and
          the recording stay until you remove them.
        </li>
        <li>
          Resources launched through the desktop broker keep their own lifetime, as they were
          started to.
        </li>
      </ul>
    </Sheet>
  )
}

/**
 * Settings, over the session rather than instead of it.
 *
 * The session is still behind this, still running and still connected. That is the whole reason it
 * is a sheet: a person changing the appearance has not left what they were doing.
 */
function SessionSettings({
  open,
  sessionId,
  subject,
  onClose
}: {
  readonly open: boolean
  readonly sessionId: string
  readonly subject: SessionSubject
  readonly onClose: () => void
}): ReactNode {
  const { port, say } = useApp()
  const [tab, setTab] = useState<'appearance' | 'session' | 'sharing' | 'export'>('appearance')
  const [followOutput, setFollowOutput] = useState(true)
  const [explained, setExplained] = useState(false)

  return (
    <Sheet open={open} title="Settings" description="The session behind this keeps running." onClose={onClose}>
      <div className="settings-layout">
        <nav className="settings-nav" aria-label="Settings sections">
          {(
            [
              ['appearance', 'Appearance'],
              ['session', 'This session'],
              ['sharing', 'Sharing'],
              ['export', 'Export']
            ] as const
          ).map(([value, label]) => (
            <button
              key={value}
              type="button"
              aria-selected={tab === value}
              className={tab === value ? 'active' : ''}
              onClick={() => {
                setTab(value)
              }}
            >
              {label}
            </button>
          ))}
        </nav>
        <div className="settings-content">
          {tab === 'appearance' ? (
            <>
              <h2>Appearance</h2>
              <p className="muted">Light, dark, or whatever this device is set to.</p>
              <ThemeChooser />
            </>
          ) : null}

          {tab === 'session' ? (
            <>
              <h2>This session</h2>
              <div className="settings-row">
                <div>
                  <h3>Follow new output</h3>
                  <p>While you are at the live end. Scrolling up stops it until you come back.</p>
                </div>
                <Switch checked={followOutput} label="Follow new output" onChange={setFollowOutput} />
              </div>
              <div className="settings-row">
                <div>
                  <h3>Conversation and process</h3>
                  <p>
                    The conversation outlives the agent that wrote it. The terminal process keeps
                    running when every view disconnects. These are different things and this
                    application keeps them apart.
                  </p>
                </div>
              </div>
            </>
          ) : null}

          {tab === 'sharing' ? (
            <>
              <h2>Sharing</h2>
              <p className="muted">
                A viewer sees the live screen. A reviewer also sees diffs and files.
              </p>
              <div className="settings-row">
                <div>
                  <h3>Let them answer the agent&apos;s questions</h3>
                  <p data-testid="answering-explanation">
                    Any answer, including free text, is input the agent may act on under your host&apos;s
                    permissions. A form does not reduce that. This is the same authority as an
                    unrestricted prompt or terminal control.
                  </p>
                </div>
                <Switch
                  checked={explained}
                  label="Let a viewer or reviewer answer questions"
                  onChange={setExplained}
                />
              </div>
              <Button
                data-testid="invite-viewer"
                onClick={() => {
                  port
                    .grantCreate(
                      {
                        session_id: sessionId,
                        role: 'viewer',
                        rights: explained
                          ? ['session.view', 'question.respond']
                          : ['session.view'],
                        answering_explained: explained
                      },
                      subject
                    )
                    .then((result) => {
                      say(outcomeMessage('Invitation issued', result.receipt), receiptTone(result.receipt))
                    })
                    .catch((error: unknown) => {
                      say(failureMessage(error), 'danger')
                    })
                }}
              >
                Invite a viewer
              </Button>
            </>
          ) : null}

          {tab === 'export' ? <ExportPanel sessionId={sessionId} /> : null}
        </div>
      </div>
    </Sheet>
  )
}

/** Two exports, both to a file the person picks. */
function ExportPanel({ sessionId }: { readonly sessionId: string }): ReactNode {
  const { port, say } = useApp()

  const exportSemantic = () => {
    void port.chooseExportPath(`session-${sessionId}.json`).then((path) => {
      if (!path) return
      port
        .agentSnapshot({ session_id: sessionId })
        .then((snapshot) =>
          port.exportSemanticJson({
            path,
            sessionId,
            exportedAtMs: Date.now(),
            dimensions: { columns: 120, rows: 40 },
            nodes: snapshot.nodes.map((node) => ({
              id: node.id,
              revision: node.revision,
              body: node.body,
              at_ms: Date.now()
            })),
            omissions: []
          })
        )
        .then((written) => {
          say(`Written to ${written.path}.`)
        })
        .catch((error: unknown) => {
          say(failureMessage(error), 'danger')
        })
    })
  }

  const exportRecording = () => {
    void port.chooseExportPath(`session-${sessionId}.cast`).then((path) => {
      if (!path) return
      port
        .exportAsciicast({
          path,
          title: `Session ${sessionId}`,
          startedAtUnixSeconds: Math.floor(Date.now() / 1000),
          dimensions: { columns: 120, rows: 40 },
          frames: [],
          omissions: []
        })
        .then((written) => {
          say(
            written.omissions.length > 0
              ? `Written to ${written.path}, with ${written.omissions.length} declared omission${written.omissions.length === 1 ? '' : 's'}.`
              : `Written to ${written.path}.`
          )
        })
        .catch((error: unknown) => {
          say(failureMessage(error), 'danger')
        })
    })
  }

  return (
    <>
      <h2>Export</h2>
      <p className="muted">
        Both write a file where you choose. Nothing is uploaded, and both say what they left out.
      </p>
      <Card>
        <div className="card-body">
          <div className="divided-row">
            <div className="spacer">
              <strong>Semantic archive</strong>
              <p className="muted small">
                The conversation as JSON, with its timestamps, the terminal size and anything the
                archive does not carry.
              </p>
            </div>
            <Button data-testid="export-json" onClick={exportSemantic}>
              Export JSON
            </Button>
          </div>
          <div className="divided-row">
            <div className="spacer">
              <strong>Terminal recording</strong>
              <p className="muted small">
                An asciicast. Sequences that would act on the machine that plays it back, such as a
                clipboard write, are removed and declared.
              </p>
            </div>
            <Button data-testid="export-cast" onClick={exportRecording}>
              Export recording
            </Button>
          </div>
        </div>
      </Card>
      <p className="small faint">
        <Badge tone="neutral">Session {sessionId.slice(-4)}</Badge>
      </p>
    </>
  )
}
