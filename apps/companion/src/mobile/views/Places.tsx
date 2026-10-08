/**
 * Hosts and sessions, as a phone lists them.
 *
 * Both are the same shape: a list of rows that lead somewhere. A host that is not in contact says
 * so and says nothing more, because that is all this device knows about it.
 */

import { useEffect, useState, type ReactNode } from 'react'

import type { EnvironmentListResult, SessionListResult } from '@kalareach/protocol'

import { useApp } from '../../app/state'
import { failureMessage, watch, type Watch } from '../../host/port'
import { Banner } from '../../components/ui'
import { PairingFlow } from '../../pairing/PairingFlow'
import { accountName } from '../../views/account-name'
import {
  activityLine,
  applicationName,
  directoryName,
  freshnessNote,
  shownTitle,
  sourceLabel,
  useDescriptions,
  useOnScreen
} from '../../model/describe'
import { ask } from '../model/call'
import { minimumTarget, type Surface } from '../platform'

interface Row {
  readonly id: string
  readonly title: string
  /** The directory's own name, which a row says until the host has described its session. */
  readonly directory?: string
  readonly where: string
  readonly detail: string
  readonly tone: 'muted' | 'success' | 'warning'
}

/** The sessions on every host this device can see. */
export function MobileSessions({
  surface,
  onOpen,
  onOpenVoice
}: {
  readonly surface: Surface
  readonly onOpen: (sessionId: string) => void
  /** Opens the voice screen. Absent while no host is reached, when there is no one to talk to. */
  readonly onOpenVoice?: () => void
}): ReactNode {
  const { port } = useApp()
  const [rows, setRows] = useState<readonly Row[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const target = minimumTarget(surface)
  // The host is asked about the rows a person can see, and the few either side of them.
  const { onScreen, track } = useOnScreen()
  const descriptions = useDescriptions(
    port,
    (rows ?? []).filter((row) => onScreen.has(row.id)).map((row) => row.id),
    rows
  )

  // The list is read under a watch with no listeners, one for each port, so only the newest read's
  // answer or failure is shown, and nothing once the list has gone.
  useEffect(() => {
    const reads: Watch = watch([], () => {
      const current = reads.read()
      if (current === null) return
      ask(() => port.sessionList({}))
        .then((answer) => {
          if (!current()) return
          const sessions = (answer satisfies SessionListResult).sessions ?? []
          setRows(
            sessions.map((session) => ({
              id: session.session_id,
              title: `Session ${session.display_number}`,
              directory: directoryName(session.cwd),
              where: session.cwd,
              // The application in the foreground comes first, as it does in the desktop's list. A
              // stock shell is labelled wherever the session is listed.
              detail:
                session.shell_mode === 'native_compat'
                  ? `${applicationName(session)} · ${describeSessionState(session.state, session.attachment_count)} · Stock shell`
                  : `${applicationName(session)} · ${describeSessionState(session.state, session.attachment_count)}`,
              tone: session.state === 'live' ? 'success' : session.state === 'closed' ? 'muted' : 'warning'
            }))
          )
          setError(null)
        })
        .catch((failure: unknown) => {
          if (!current()) return
          setError(failureMessage(failure))
        })
    })
    return reads.stop
  }, [port])

  return (
    <>
      {onOpenVoice === undefined ? null : (
        <button
          type="button"
          className="m-row"
          data-testid="voice-entry"
          style={{ minBlockSize: target }}
          onClick={onOpenVoice}
        >
          <span className="m-row-title">Talk to your host</span>
          <span className="m-row-detail">Voice, for the sessions you choose</span>
        </button>
      )}
      {error ? (
        <Banner tone="warning" title="The sessions could not be read" detail={error} />
      ) : null}
      {rows && rows.length === 0 ? <p className="m-empty">No sessions on this host.</p> : null}
      {rows && rows.length > 0 ? (
        <ul className="m-list">
          {rows.map((row) => {
            const described = descriptions.get(row.id)
            const label = sourceLabel(described)
            const activity = activityLine(described)
            const overtaken = freshnessNote(described)
            return (
              <li key={row.id}>
                <button
                  type="button"
                  className="m-row"
                  data-tone={row.tone}
                  data-session={row.id}
                  ref={track}
                  style={{ minBlockSize: target }}
                  onClick={() => {
                    onOpen(row.id)
                  }}
                >
                  <span className="m-row-title">{row.title}</span>
                  <span className="m-row-description" data-testid="description-title">
                    {shownTitle(row.directory ?? row.where, described)}
                    {label ? (
                      <span className="m-row-label" data-testid="description-source">
                        {' '}
                        {label}
                      </span>
                    ) : null}
                  </span>
                  {activity ? (
                    <span className="m-row-activity" data-testid="description-activity">
                      {activity}
                      {overtaken ? (
                        <span className="m-row-note" data-testid="description-freshness">
                          {' '}
                          {overtaken}
                        </span>
                      ) : null}
                    </span>
                  ) : null}
                  <span className="m-row-where">{row.where}</span>
                  <span className="m-row-detail">{row.detail}</span>
                </button>
              </li>
            )
          })}
        </ul>
      ) : null}
      {!rows && !error ? <p className="m-empty">Reading the sessions…</p> : null}
    </>
  )
}

/**
 * The hosts this device is paired with, and the way to pair another.
 *
 * A phone has no host of its own: it pairs with one, and its commands go to the one it uses. The
 * list under the pairing entry is what that host reports of its environments, read again whenever
 * the connection comes or goes.
 */
export function MobileHosts({
  surface,
  connected
}: {
  readonly surface: Surface
  /** Whether a host is being reached now, or null before anything has said. */
  readonly connected?: boolean | null
}): ReactNode {
  const { port } = useApp()
  const [rows, setRows] = useState<readonly Row[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const target = minimumTarget(surface)

  // Read as the session list is: only the newest read shows, and nothing once the list has gone.
  useEffect(() => {
    const reads: Watch = watch([], () => {
      const current = reads.read()
      if (current === null) return
      ask(() => port.environmentList())
        .then((answer: EnvironmentListResult) => {
          if (!current()) return
          setRows(
            answer.environments.map((environment) => ({
              id: environment.environment_id,
              title: environment.label,
              where: `${environment.os} · ${environment.arch} · ${accountName(environment)}`,
              // What this device knows is how many sessions the host reported. It knows nothing
              // about a host it has not heard from, and says nothing about one.
              detail: `${environment.live_sessions} live ${environment.live_sessions === '1' ? 'session' : 'sessions'}`,
              tone: 'success' as const
            }))
          )
          setError(null)
        })
        .catch((failure: unknown) => {
          if (!current()) return
          setError(failureMessage(failure))
        })
    })
    return reads.stop
  }, [port, connected])

  return (
    <>
      <PairingFlow
        chooseHost={async (reference) => {
          await port.hostsUse(reference)
        }}
      />
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
      ) : null}
      {!rows && !error ? <p className="m-empty">Reading the hosts…</p> : null}
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
