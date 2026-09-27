/**
 * Sharing a session with a paired device: an invitation, and the grants already issued.
 *
 * Section 25 sets the rules this screen keeps. A viewer sees the live screen and what follows, and a
 * reviewer also sees diffs and files. Only a controller or an owner answers the agent's questions
 * by default; a viewer or reviewer can be given that too, through an option that explains what it
 * means first, because any answer, free text included, is input the agent may act on under its own
 * permissions. What an invitation would carry is shown before it exists, in the protocol's own
 * sentences, and issuing it sends those same consequences back for the host to check: a surface
 * that showed a softer set cannot get the grant written. An invitation is used once and expires,
 * one hour after it is issued unless the issuer chose otherwise.
 */

import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react'

import type {
  ActionRight,
  DeviceListResult,
  GrantListResult,
  RoleSelection
} from '@kalareach/protocol'

import { Badge, Banner, Button, Card, CommitButton, Segmented, Switch } from '../components/ui'
import { useApp } from '../app/state'
import {
  failureMessage,
  watch,
  type GrantNotices,
  type SessionSubject,
  type Watch
} from '../host/port'
import { ask } from '../mobile/model/call'
import { answeredState, outcomeMessage, outcomeTone } from '../model/receipts'

/** What each action lets a recipient do, in words. */
const ACTION_WORDS: Partial<Readonly<Record<ActionRight, string>>> = {
  'session.view': 'See the live screen and what follows it',
  'files.read': 'Read the diffs and files it is shown',
  'question.respond': 'Answer the agent’s questions',
  'terminal.input': 'Type into the terminal',
  'agent.prompt': 'Send the agent prompts',
  'agent.cancel': 'Cancel the agent’s turn',
  'agent.approval.respond': 'Answer the agent’s approval requests'
}

/** The roles an invitation from here offers: the two that never type or prompt. */
type Role = 'viewer' | 'reviewer'

/** The selection an invitation carries: a role and the one explicit choice this screen offers. */
function selectionOf(role: Role, answering: boolean): RoleSelection {
  return {
    role,
    history_from_cursor_ms: null,
    include_live_screen: false,
    include_question_respond: answering,
    named_questions: [],
    named_approvals: []
  }
}

/** Sharing, over one session. */
export function Sharing({
  sessionId,
  subject
}: {
  readonly sessionId: string
  readonly subject: SessionSubject
}): ReactNode {
  const { port, say } = useApp()
  const [devices, setDevices] = useState<DeviceListResult | null>(null)
  const [grants, setGrants] = useState<GrantListResult | null>(null)
  const [failure, setFailure] = useState<string | null>(null)
  const [recipient, setRecipient] = useState<string | null>(null)
  const [role, setRole] = useState<Role>('viewer')
  const [answering, setAnswering] = useState(false)
  // What the invitation as chosen would carry, for the choice it was read for.
  const [notices, setNotices] = useState<{
    readonly key: string
    readonly notices: GrantNotices
  } | null>(null)
  const [issuing, setIssuing] = useState(false)
  const reads = useRef<Watch | null>(null)

  const load = useCallback(() => {
    const current = reads.current?.read() ?? null
    if (current === null) return
    ask(() =>
      Promise.all([
        port.deviceList({ include_revoked: false }),
        port.grantList({ session_id: sessionId, include_resolved: false })
      ])
    )
      .then(([paired, issued]) => {
        if (!current()) return
        setDevices(paired)
        setGrants(issued)
        setFailure(null)
      })
      .catch((error: unknown) => {
        if (!current()) return
        setFailure(failureMessage(error))
      })
  }, [port, sessionId])

  useEffect(() => {
    const reading = watch([], load)
    reads.current = reading
    return () => {
      reading.stop()
      if (reads.current === reading) reads.current = null
    }
  }, [load])

  // The consequences are read for each choice the person makes, and only the newest is shown.
  const choice = `${role}:${String(answering)}`
  useEffect(() => {
    let current = true
    ask(() => port.grantNotices(selectionOf(role, answering)))
      .then((carried) => {
        if (current) setNotices({ key: `${role}:${String(answering)}`, notices: carried })
      })
      .catch((error: unknown) => {
        if (current) setFailure(failureMessage(error))
      })
    return () => {
      current = false
    }
  }, [port, role, answering])

  const shown = notices?.key === choice ? notices.notices : null
  const paired = devices?.devices.filter((device) => !device.revoked) ?? []
  const chosen = paired.find((device) => device.device_id === recipient) ?? null

  const issue = () => {
    if (chosen === null || shown === null) return
    setIssuing(true)
    ask(() =>
      port.grantCreate(
        {
          session_id: sessionId,
          recipient_device_id: chosen.device_id,
          parent_grant_id: null,
          selection: selectionOf(role, answering),
          lifetime_ms: null,
          accepted_notices: shown.notices.map((each) => each.notice),
          owner_confirmation: null
        },
        subject
      )
    )
      .then((settled) => {
        const expires = settled.value?.preview.expires_at_ms
        say(
          answeredState(settled) === 'applied' && expires !== undefined
            ? `Invitation issued to ${chosen.display_name}. It is used once, and expires at ${new Date(Number(expires)).toLocaleTimeString()}.`
            : outcomeMessage(`Invitation issued to ${chosen.display_name}`, settled),
          outcomeTone(settled)
        )
        load()
      })
      .catch((error: unknown) => {
        say(failureMessage(error), 'danger')
      })
      .finally(() => {
        setIssuing(false)
      })
  }

  const names = new Map((devices?.devices ?? []).map((device) => [device.device_id, device.display_name]))

  return (
    <>
      <h2>Sharing</h2>
      <p className="muted">
        Invite a device paired with this host. An invitation is used once and expires one hour after
        it is issued.
      </p>

      {failure ? (
        <Banner
          tone="warning"
          title="Sharing could not be read"
          detail={failure}
          action={<Button onClick={load}>Try again</Button>}
        />
      ) : null}

      <fieldset className="settings-group" data-testid="recipients">
        <legend>Who it is for</legend>
        {devices !== null && paired.length === 0 ? (
          <p className="small muted" data-testid="no-devices">
            No device is paired with this host. Pair the device first, from that device.
          </p>
        ) : null}
        {paired.map((device) => (
          <label className="choice-row" key={device.device_id}>
            <input
              type="radio"
              name={`recipient-${sessionId}`}
              value={device.device_id}
              checked={recipient === device.device_id}
              onChange={() => {
                setRecipient(device.device_id)
              }}
            />
            <span>
              {device.display_name}
              <span className="small faint">
                {' '}
                · paired {new Date(Number(device.paired_at_ms)).toLocaleDateString()}
              </span>
            </span>
          </label>
        ))}
      </fieldset>

      <div className="settings-row">
        <div>
          <h3>What they can do</h3>
          <p>A viewer sees the live screen. A reviewer also sees diffs and files.</p>
        </div>
        <Segmented
          label="Role"
          value={role}
          options={[
            { value: 'viewer', label: 'Viewer' },
            { value: 'reviewer', label: 'Reviewer' }
          ]}
          onChange={setRole}
        />
      </div>

      <div className="settings-row">
        <div>
          <h3>Let them answer the agent&apos;s questions</h3>
          <p data-testid="answering-explanation">
            Any answer, including free text, is input the agent may act on under your host&apos;s
            permissions. A form does not reduce that. This is the same authority as an unrestricted
            prompt or terminal control.
          </p>
        </div>
        <Switch
          checked={answering}
          label="Let a viewer or reviewer answer questions"
          onChange={setAnswering}
        />
      </div>

      <Card data-testid="invitation-carries">
        <div className="card-body">
          <h3>This invitation carries</h3>
          <ul className="consequence-list">
            {(shown?.actions ?? []).map((action) => (
              <li key={action}>{ACTION_WORDS[action] ?? action}</li>
            ))}
          </ul>
          {(shown?.notices ?? []).map((each) => (
            <p className="small warning-text" key={each.notice} data-notice={each.notice}>
              {each.sentence}
            </p>
          ))}
        </div>
      </Card>

      <CommitButton
        data-testid="invite"
        disabled={chosen === null || shown === null || issuing}
        onCommit={issue}
      >
        {chosen === null ? 'Choose a device to invite' : `Invite ${chosen.display_name}`}
      </CommitButton>

      {(grants?.grants.length ?? 0) > 0 ? (
        <>
          <h3>Issued for this session</h3>
          <Card data-testid="issued-grants">
            <div className="card-body">
              {(grants?.grants ?? []).map((summary) => {
                const expiry = summary.grant.expiry
                return (
                  <div className="divided-row" key={summary.grant.grant_id}>
                    <span className="spacer">
                      {names.get(summary.grant.recipient_device_id) ?? 'A paired device'}
                      <span className="small faint">
                        {' '}
                        ·{' '}
                        {summary.grant.actions
                          .map((action) => ACTION_WORDS[action] ?? action)
                          .join('; ')}
                      </span>
                    </span>
                    <Badge tone={summary.state === 'active' ? 'success' : 'neutral'}>
                      {summary.state === 'pending' ? 'Waiting to be used' : summary.state}
                    </Badge>
                    {typeof expiry === 'object' ? (
                      <span className="small faint">
                        until {new Date(Number(expiry.at.expires_at_ms)).toLocaleString()}
                      </span>
                    ) : null}
                  </div>
                )
              })}
            </div>
          </Card>
        </>
      ) : null}
    </>
  )
}
