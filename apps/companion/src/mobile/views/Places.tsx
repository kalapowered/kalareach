/**
 * Hosts and sessions, as a phone lists them.
 *
 * Both are the same shape: a list of rows that lead somewhere. A host that is not in contact says
 * so and says nothing more, because that is all this device knows about it.
 */

import { useCallback, useEffect, useState, type ReactNode } from 'react'

import type { EnvironmentListResult, SessionListResult } from '@kalareach/protocol'

import { useApp } from '../../app/state'
import { failureMessage } from '../../host/port'
import { Banner } from '../../components/ui'
import { accountName } from '../../views/account-name'
import { ask } from '../model/call'
import { minimumTarget, type Surface } from '../platform'

interface Row {
  readonly id: string
  readonly title: string
  readonly where: string
  readonly detail: string
  readonly tone: 'muted' | 'success' | 'warning'
}

/** The sessions on every host this device can see. */
export function MobileSessions({
  surface,
  onOpen
}: {
  readonly surface: Surface
  readonly onOpen: (sessionId: string) => void
}): ReactNode {
  const { port } = useApp()
  const [rows, setRows] = useState<readonly Row[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const target = minimumTarget(surface)

  const read = useCallback(() => {
    ask(() => port.sessionList({}))
      .then((answer) => {
        const sessions = (answer satisfies SessionListResult).sessions ?? []
        setRows(
          sessions.map((session) => ({
            id: session.session_id,
            title: `Session ${session.display_number}`,
            where: session.cwd,
            detail: describeSessionState(session.state, session.attachment_count),
            tone: session.state === 'live' ? 'success' : session.state === 'closed' ? 'muted' : 'warning'
          }))
        )
        setError(null)
      })
      .catch((failure: unknown) => {
        setError(failureMessage(failure))
      })
  }, [port])

  useEffect(read, [read])

  return (
    <>
      {error ? (
        <Banner tone="warning" title="The sessions could not be read" detail={error} />
      ) : null}
      {rows && rows.length === 0 ? <p className="m-empty">No sessions on this host.</p> : null}
      {rows && rows.length > 0 ? (
        <ul className="m-list">
          {rows.map((row) => (
            <li key={row.id}>
              <button
                type="button"
                className="m-row"
                data-tone={row.tone}
                data-session={row.id}
                style={{ minBlockSize: target }}
                onClick={() => {
                  onOpen(row.id)
                }}
              >
                <span className="m-row-title">{row.title}</span>
                <span className="m-row-where">{row.where}</span>
                <span className="m-row-detail">{row.detail}</span>
              </button>
            </li>
          ))}
        </ul>
      ) : null}
      {!rows && !error ? <p className="m-empty">Reading the sessions…</p> : null}
    </>
  )
}

/** The hosts this device is paired with. */
export function MobileHosts({ surface }: { readonly surface: Surface }): ReactNode {
  const { port } = useApp()
  const [rows, setRows] = useState<readonly Row[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const target = minimumTarget(surface)

  useEffect(() => {
    ask(() => port.environmentList())
      .then((answer: EnvironmentListResult) => {
        setRows(
          answer.environments.map((environment) => ({
            id: environment.environment_id,
            title: environment.label,
            where: `${environment.os} · ${environment.arch} · ${accountName(environment.os_user)}`,
            // What this device knows is how many sessions the host reported. It knows nothing
            // about a host it has not heard from, and says nothing about one.
            detail: `${environment.live_sessions} live ${environment.live_sessions === '1' ? 'session' : 'sessions'}`,
            tone: 'success' as const
          }))
        )
        setError(null)
      })
      .catch((failure: unknown) => {
        setError(failureMessage(failure))
      })
  }, [port])

  return (
    <>
      {error ? <Banner tone="warning" title="The hosts could not be read" detail={error} /> : null}
      {rows ? (
        <ul className="m-list">
          {rows.map((row) => (
            <li key={row.id}>
              <div className="m-row" data-tone={row.tone} style={{ minBlockSize: target }}>
                <span className="m-row-title">{row.title}</span>
                <span className="m-row-where">{row.where}</span>
                <span className="m-row-detail">{row.detail}</span>
              </div>
            </li>
          ))}
        </ul>
      ) : (
        <p className="m-empty">Reading the hosts…</p>
      )}
    </>
  )
}

/** What a session's state and attachment count say, in words. */
function describeSessionState(state: string, attachments: string): string {
  const joined = `${attachments} ${attachments === '1' ? 'view' : 'views'} attached`
  switch (state) {
    case 'live':
      return `Live · ${joined}`
    case 'creating':
      return 'Starting'
    case 'closing':
      return 'Closing'
    case 'closed':
      return 'Closed'
    default:
      return state
  }
}
