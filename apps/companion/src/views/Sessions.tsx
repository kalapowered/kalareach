/**
 * Sessions and Hosts.
 *
 * A session row carries the six things section 13 names: the display number, the description, the
 * directory, the application in the foreground, how many views are attached, and its state. Nothing
 * on the row is inferred from elapsed time.
 */

import { useCallback, useEffect, useState, type ReactNode } from 'react'

import type { EnvironmentListResult, HostInfoResult, SessionListResult } from '@kalareach/protocol'

import { Badge, Banner, Button, Card } from '../components/ui'
import { useApp } from '../app/state'
import { failureMessage } from '../host/port'

type Session = SessionListResult['sessions'][number]

/** What the application state is called, in words rather than in wire values. */
export function describeApplicationState(session: Session): {
  readonly label: string
  readonly tone: 'neutral' | 'warning' | 'success' | 'accent'
} {
  if (session.state === 'closed') return { label: 'Closed', tone: 'neutral' }
  if (session.state === 'closing') return { label: 'Closing', tone: 'warning' }
  switch (session.application_state) {
    case 'awaiting_approval':
      return { label: 'Waiting for you', tone: 'warning' }
    case 'agent_busy':
      return { label: 'Working', tone: 'accent' }
    case 'awaiting_input':
      return { label: 'Waiting for input', tone: 'accent' }
    case 'shell_ready':
      return { label: 'Shell ready', tone: 'success' }
    default:
      // A host that has not told this client what the foreground is doing has not told it. The
      // row says so rather than guessing from how long it has been quiet.
      return { label: 'Not reported', tone: 'neutral' }
  }
}

/** The name a session shows. The host derives it; this never invents one. */
export function sessionDescription(session: Session): string {
  const folder = session.cwd.split('/').filter(Boolean).pop() ?? session.cwd
  return folder
}

/** The list of sessions. */
export function Sessions(): ReactNode {
  const { port, go } = useApp()
  const [list, setList] = useState<SessionListResult | null>(null)
  const [failure, setFailure] = useState<string | null>(null)
  const [query, setQuery] = useState('')

  const load = useCallback(() => {
    port
      .sessionList({})
      .then((result) => {
        setList(result)
        setFailure(null)
      })
      .catch((error: unknown) => {
        setFailure(failureMessage(error))
      })
  }, [port])

  useEffect(load, [load])

  const sessions = (list?.sessions ?? []).filter((session) => {
    if (query.trim().length === 0) return true
    const needle = query.toLowerCase()
    return (
      session.cwd.toLowerCase().includes(needle) ||
      session.display_number.includes(needle) ||
      sessionDescription(session).toLowerCase().includes(needle)
    )
  })

  return (
    <>
      <header className="page-heading">
        <div>
          <p className="eyebrow">Sessions</p>
          <h1>Sessions</h1>
          <p>Everything running on this host, and what each one is doing.</p>
        </div>
      </header>

      {failure ? (
        <Banner
          tone="warning"
          title="This host is not answering"
          detail={`${failure} Its sessions may still be running.`}
          action={<Button onClick={load}>Try again</Button>}
        />
      ) : null}

      <div className="toolbar">
        <label className="search-field">
          <span className="visually-hidden">Search sessions</span>
          <input
            type="search"
            value={query}
            placeholder="Search by number or directory"
            onChange={(event) => {
              setQuery(event.target.value)
            }}
          />
        </label>
      </div>

      <div className="session-table" role="table" aria-label="Sessions">
        <div className="table-head" role="row">
          <span role="columnheader">Session</span>
          <span role="columnheader">Directory</span>
          <span role="columnheader">Application</span>
          <span role="columnheader">Attached</span>
          <span role="columnheader">State</span>
        </div>
        {sessions.map((session) => {
          const state = describeApplicationState(session)
          return (
            <button
              key={session.session_id}
              type="button"
              className="session-row"
              role="row"
              data-testid={`session-row-${session.display_number}`}
              onClick={() => {
                go({ view: 'session', sessionId: session.session_id, pane: 'semantic' })
              }}
            >
              <span className="row" role="cell">
                <span className="session-number mono">{session.display_number}</span>
                <span>
                  <h3>{sessionDescription(session)}</h3>
                  <p className="faint mono">{session.shell_path}</p>
                </span>
              </span>
              <span className="host-column mono" role="cell">
                {session.cwd}
              </span>
              <span className="agent-column" role="cell">
                {session.application_state === null ? 'Shell' : 'Agent'}
              </span>
              <span className="agent-column" role="cell" data-testid="attachment-count">
                {session.attachment_count}
              </span>
              <span role="cell">
                <Badge tone={state.tone}>{state.label}</Badge>
              </span>
            </button>
          )
        })}
      </div>
    </>
  )
}

/** The hosts, their environments and whether a desktop is available. */
export function Hosts(): ReactNode {
  const { port } = useApp()
  const [info, setInfo] = useState<HostInfoResult | null>(null)
  const [environments, setEnvironments] = useState<EnvironmentListResult | null>(null)
  const [reachable, setReachable] = useState(true)
  const [failure, setFailure] = useState<string | null>(null)

  const load = useCallback(() => {
    Promise.all([port.hostInfo(), port.environmentList()])
      .then(([hostInfo, list]) => {
        setInfo(hostInfo)
        setEnvironments(list)
        setReachable(true)
        setFailure(null)
      })
      .catch((error: unknown) => {
        setReachable(false)
        setFailure(failureMessage(error))
      })
  }, [port])

  useEffect(load, [load])

  return (
    <>
      <header className="page-heading">
        <div>
          <p className="eyebrow">Hosts</p>
          <h1>Hosts</h1>
          <p>The machines you have paired, and what each one can run.</p>
        </div>
        <div className="page-actions">
          <Button onClick={load}>Refresh</Button>
        </div>
      </header>

      {!reachable ? (
        <Banner
          tone="warning"
          title="Disconnected"
          detail={`${failure ?? 'This host cannot be contacted.'} Its sessions may still be running; nothing here says they are not.`}
          action={<Button onClick={load}>Try again</Button>}
        />
      ) : null}

      <Card>
        <div className="card-header">
          <div className="spacer">
            <h2>studio</h2>
            <p className="muted small">
              {reachable ? 'Connected' : 'Not in contact'}
              {info ? ` · build ${info.build_id}` : ''}
            </p>
          </div>
          <Badge tone={reachable ? 'success' : 'neutral'}>
            {reachable ? 'Connected' : 'Disconnected'}
          </Badge>
        </div>
        <div className="card-body">
          {(environments?.environments ?? []).map((environment) => (
            <div className="divided-row" key={environment.environment_id}>
              <div className="spacer">
                <strong>{environment.label}</strong>
                <p className="muted small mono">
                  {environment.os} · {environment.arch} · {environment.os_user}
                </p>
              </div>
              <span className="row">
                <Badge tone="neutral">{environment.live_sessions} live</Badge>
                <Badge tone="success">Desktop ready</Badge>
              </span>
            </div>
          ))}
          {environments === null ? <p className="muted small">Nothing to show yet.</p> : null}
        </div>
      </Card>
    </>
  )
}
