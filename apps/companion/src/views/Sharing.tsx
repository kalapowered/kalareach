/**
 * Sharing a session with a paired device: who has access, an invitation, and handing control over.
 *
 * Section 25 sets the rules this screen keeps. The list of who has access comes first, then the
 * form, and every control in the form is an explicit choice: nothing is on until the person turns
 * it on. What an invitation would carry is shown before it exists, in the protocol's own sentences,
 * and issuing it sends those same consequences back for the host to check, so a surface that
 * showed a softer set cannot get the grant written. With the live view on, the person is shown the
 * lines on the screen as they are read, and the card says what that preview is not: the recipient
 * is drawn the screen as it is when they open it, and what follows.
 *
 * The four actions that change who holds a session are attempts native code keeps its word about.
 * An answer the host gave and the connection lost is something to ask the host about, never to
 * send again; this screen lists such an attempt as unfinished with the one thing the person can do
 * about it, and says when it can no longer happen.
 */

import { useCallback, useEffect, useId, useRef, useState, type ReactNode } from 'react'

import type {
  ActionRight,
  DeviceListResult,
  DeviceSummary,
  GrantCreateResult,
  GrantListResult,
  GrantSummary,
  RevocationResult,
  RoleSelection
} from '@kalareach/protocol'

import { Badge, Banner, Button, Card, CommitButton, Switch } from '../components/ui'
import { useApp } from '../app/state'
import {
  failureMessage,
  watch,
  type AttemptView,
  type GrantNotices,
  type SessionSubject,
  type Watch
} from '../host/port'
import { ask } from '../mobile/model/call'
import {
  HISTORY_CHOICES,
  ROLES,
  actionWords,
  attemptWords,
  defaultLasting,
  historyFrom,
  isOpen,
  lastings,
  lifetimeMs,
  momentWords,
  pairingEnd,
  platformWords,
  roleOfRights,
  roleWords,
  spanWords,
  stateWords,
  visibly,
  whyNot,
  type OfferedRole
} from '../model/sharing'
import { Transfer } from './Transfer'

/** How often the list of who has access is read again while the screen is open. */
const READ_EVERY_MS = 5000

/** The person's clock, read where an action is taken and not while a screen is drawn. */
const clock = { now: (): number => Date.now() }

/** A screen preview, as the person is shown it. */
type Preview =
  | { readonly state: 'off' }
  | { readonly state: 'reading' }
  | {
      readonly state: 'ready'
      readonly key: string
      readonly lines: readonly string[]
      readonly truncated: boolean
      readonly readAt: number
    }

/** A revocation the screen has just made, kept because the list drops resolved grants. */
interface Revoked {
  readonly grantId: string
  readonly name: string
  readonly atMs: number
  readonly pending: number
  /** The attempt that holds the line, when the revocation was carried on after its command. */
  readonly action?: string
}

/** How many workers a revocation still waits for. */
function pendingWorkers(result: RevocationResult): number {
  return result.barrier.workers.filter((worker) => worker.state === 'pending').length
}

/** The selection an invitation as chosen carries. */
function selectionOf(
  role: OfferedRole,
  live: boolean,
  history: string,
  answering: boolean,
  nowMs: number
): RoleSelection {
  return {
    role,
    history_from_cursor_ms: historyFrom(history, nowMs),
    include_live_screen: live,
    include_question_respond: role === 'viewer' && answering,
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
  const [attempts, setAttempts] = useState<readonly AttemptView[]>([])
  const [failure, setFailure] = useState<string | null>(null)
  const [now, setNow] = useState(() => clock.now())
  const [revoked, setRevoked] = useState<readonly Revoked[]>([])
  const [handing, setHanding] = useState<GrantSummary | null>(null)
  const [changed, setChanged] = useState<readonly string[] | null>(null)
  const reads = useRef<Watch | null>(null)
  const handled = useRef(new Set<string>())
  const headingId = useId()
  const heading = useRef<HTMLHeadingElement | null>(null)
  const focusNext = useRef<string | null>(null)
  const returnTo = useRef<string | null>(null)

  // The form.
  const [recipient, setRecipient] = useState<string | null>(null)
  const [role, setRole] = useState<OfferedRole>('viewer')
  const [live, setLive] = useState(false)
  const [history, setHistory] = useState('none')
  const [answering, setAnswering] = useState(false)
  const [lasting, setLasting] = useState<string | null>(null)
  const [consentFor, setConsentFor] = useState<string | null>(null)
  const [previewFailure, setPreviewFailure] = useState<string | null>(null)
  const [issuing, setIssuing] = useState(false)
  const [notices, setNotices] = useState<{
    readonly key: string
    readonly notices: GrantNotices
  } | null>(null)

  const load = useCallback((): Promise<void> => {
    const current = reads.current?.read() ?? null
    if (current === null) return Promise.resolve()
    return ask(() =>
      Promise.all([
        port.deviceList({ include_revoked: false }),
        port.grantList({ session_id: sessionId, include_resolved: false }),
        port.attemptsList()
      ])
    )
      .then(([paired, issued, kept]) => {
        if (!current()) return
        setDevices(paired)
        setGrants(issued)
        setAttempts(kept.attempts)
        setNow(clock.now())
        setFailure(null)
      })
      .catch((error: unknown) => {
        if (!current()) return
        setFailure(failureMessage(error))
      })
  }, [port, sessionId])

  useEffect(() => {
    const reading = watch([], () => {
      void load()
    })
    reads.current = reading
    const timer = setInterval(() => {
      void load()
    }, READ_EVERY_MS)
    const onFocus = () => {
      void load()
    }
    window.addEventListener('focus', onFocus)
    return () => {
      reading.stop()
      clearInterval(timer)
      window.removeEventListener('focus', onFocus)
      if (reads.current === reading) reads.current = null
    }
  }, [load])

  // What an invitation as chosen would carry, read for the choice it was read for.
  const noticeKey = `${role}:${String(role === 'viewer' && answering)}`
  useEffect(() => {
    let current = true
    ask(() => port.grantNotices(selectionOf(role, false, 'none', answering, clock.now())))
      .then((carried) => {
        if (current) setNotices({ key: noticeKey, notices: carried })
      })
      .catch((error: unknown) => {
        if (current) setFailure(failureMessage(error))
      })
    return () => {
      current = false
    }
  }, [port, role, answering, noticeKey])

  const shown = notices?.key === noticeKey ? notices.notices : null
  const everyone = devices?.devices ?? []
  const names = new Map(everyone.map((device) => [device.device_id, device.display_name]))
  const nameOf = (id: string): string => names.get(id) ?? 'A paired device'

  const offered = everyone.filter((device) => !device.revoked && whyNot(device, now) === null)
  const notOffered = everyone.filter((device) => !device.revoked && whyNot(device, now) !== null)
  const chosen = offered.find((device) => device.device_id === recipient) ?? null
  const options = chosen === null ? [] : lastings(chosen, now)
  const effective =
    options.find((each) => each.key === lasting) ??
    options.find((each) => each.key === defaultLasting(options)) ??
    null

  // A preview is read when the live view is turned on, and again on request or when the earlier
  // activity it follows changes. A failure leaves the switch off and gives the host's words. What
  // was read belongs to the request it answered, so a preview of an older request is never shown.
  const [previewTick, setPreviewTick] = useState(0)
  const previewKey = `${String(live)}|${history}|${role}|${String(answering)}|${String(previewTick)}`
  const [read, setRead] = useState<{
    readonly key: string
    readonly lines: readonly string[]
    readonly truncated: boolean
    readonly readAt: number
  } | null>(null)
  const preview: Preview =
    !live ? { state: 'off' } : read?.key === previewKey ? { state: 'ready', ...read } : { state: 'reading' }
  useEffect(() => {
    if (!live) return
    let current = true
    ask(() =>
      port.sessionScreenPreview({
        session_id: sessionId,
        selection: selectionOf(role, true, history, answering, clock.now())
      })
    )
      .then((answer) => {
        if (!current) return
        if (answer.screen === null) {
          setLive(false)
          setPreviewFailure('The session returned no screen to preview.')
          return
        }
        setPreviewFailure(null)
        setRead({
          key: previewKey,
          lines: answer.screen.lines,
          truncated: answer.screen.truncated,
          readAt: clock.now()
        })
      })
      .catch((error: unknown) => {
        if (!current) return
        setLive(false)
        setPreviewFailure(failureMessage(error))
      })
    return () => {
      current = false
    }
  }, [port, sessionId, live, history, role, answering, previewKey])

  const consentKey = `${recipient ?? ''}|${role}|${String(answering)}`
  const consented = consentFor === consentKey
  const carries = shown !== null && shown.notices.length > 0
  const geometry = shown?.actions.includes('terminal.geometry') === true
  const ready =
    chosen !== null &&
    effective !== null &&
    shown !== null &&
    !issuing &&
    (!carries || consented) &&
    (!live || (preview.state === 'ready' && !preview.truncated))

  // Moves focus where it belongs after a list changes: to the row just made, to the next row, or
  // to the heading when there is none.
  useEffect(() => {
    const wanted = focusNext.current
    if (wanted === null) return
    focusNext.current = null
    const row = wanted === 'heading' ? null : document.querySelector<HTMLElement>(`[data-grant="${wanted}"]`)
    ;(row ?? heading.current)?.focus()
  }, [grants])

  // Leaving the hand-over without one puts focus back on the button that opened it, which is a new
  // element: the rows were drawn again while the panel was open.
  useEffect(() => {
    if (handing !== null || returnTo.current === null) return
    const wanted = returnTo.current
    returnTo.current = null
    document
      .querySelector<HTMLElement>(`[data-grant="${wanted}"] [data-testid="hand-over-open"]`)
      ?.focus()
  }, [handing])

  // An attempt that was carried on after the command that sent it returned, and ended with the
  // host's result, is told once as the same success the command would have been. An invitation or
  // a hand-over then has no further use for its record; a revocation keeps its line, because the
  // list of grants drops resolved ones, until the person dismisses it.
  useEffect(() => {
    for (const attempt of attempts) {
      if (attempt.phase !== 'closed' || attempt.outcome !== 'happened') continue
      if (attempt.result === null || handled.current.has(attempt.action_id)) continue
      handled.current.add(attempt.action_id)
      if (attempt.kind === 'invite') {
        const made = attempt.result as GrantCreateResult
        say(`Invitation ready for ${nameOf(made.grant.recipient_device_id)}. They accept it on their device.`)
        void ask(() => port.attemptRemove(attempt.action_id)).then(load, () => undefined)
      } else if (attempt.kind === 'transfer') {
        say(`${attempt.label}: done.`)
        void ask(() => port.attemptRemove(attempt.action_id)).then(load, () => undefined)
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps -- `nameOf` reads the devices of the same render
  }, [attempts, port, say, load])

  const issue = () => {
    if (chosen === null || effective === null || shown === null) return
    const at = clock.now()
    const selection = selectionOf(role, live, history, answering, at)
    const shownLines = preview.state === 'ready' ? preview.lines : null
    setIssuing(true)
    ask(() =>
      port.grantCreate(
        {
          session_id: sessionId,
          recipient_device_id: chosen.device_id,
          parent_grant_id: null,
          selection,
          lifetime_ms: String(lifetimeMs(effective, chosen, at)),
          accepted_notices: shown.notices.map((each) => each.notice),
          owner_confirmation: null
        },
        subject
      )
    )
      .then((done) => {
        if (done.attempt.phase !== 'closed' || done.value === null) {
          say(
            `The host’s answer did not arrive. The invitation to ${chosen.display_name} is listed as unfinished; ask the host about it.`,
            'pending'
          )
        } else {
          const made = done.value
          say(`Invitation ready for ${chosen.display_name}. They accept it on their device.`)
          focusNext.current = made.grant.grant_id
          const kept = made.preview.live_screen?.lines ?? null
          if (
            shownLines !== null &&
            kept !== null &&
            JSON.stringify(kept) !== JSON.stringify(shownLines)
          ) {
            setChanged(kept)
          } else {
            setChanged(null)
          }
          setConsentFor(null)
        }
        return load()
      })
      .catch((error: unknown) => {
        say(failureMessage(error), 'danger')
      })
      .finally(() => {
        setIssuing(false)
      })
  }

  const revoke = (summary: GrantSummary, rows: readonly GrantSummary[], withdrawing: boolean) => {
    const index = rows.findIndex((each) => each.grant.grant_id === summary.grant.grant_id)
    const next = rows[index + 1] ?? rows[index - 1]
    focusNext.current = next === undefined ? 'heading' : next.grant.grant_id
    const name = nameOf(summary.grant.recipient_device_id)
    ask(() => port.grantRevoke({ grant_id: summary.grant.grant_id }))
      .then((done) => {
        if (done.value === null) {
          say(
            `The host’s answer did not arrive. The ${withdrawing ? 'withdrawal' : 'revocation'} is listed as unfinished; ask the host about it.`,
            'pending'
          )
          return
        }
        const pending = pendingWorkers(done.value)
        setRevoked((each) => [
          ...each.filter((line) => line.grantId !== summary.grant.grant_id),
          { grantId: summary.grant.grant_id, name, atMs: clock.now(), pending }
        ])
        say(
          withdrawing
            ? `Invitation to ${name} withdrawn.`
            : pending === 0
              ? `Revoked ${name}’s access.`
              : `Revoked ${name}’s access. ${String(pending)} session worker${pending === 1 ? ' has' : 's have'} not confirmed yet.`,
          pending === 0 ? 'success' : 'pending'
        )
        return load()
      })
      .catch((error: unknown) => {
        say(failureMessage(error), 'danger')
      })
  }

  const checkAgain = (line: Revoked) => {
    ask(() => port.grantRevoke({ grant_id: line.grantId }))
      .then((done) => {
        if (done.value === null) {
          say('The host’s answer did not arrive. Check again in a moment.', 'pending')
          return
        }
        const pending = pendingWorkers(done.value)
        setRevoked((each) =>
          each.map((each2) =>
            each2.grantId === line.grantId ? { ...each2, atMs: clock.now(), pending } : each2
          )
        )
      })
      .catch((error: unknown) => {
        say(failureMessage(error), 'danger')
      })
  }

  const askHost = (attempt: AttemptView) => {
    ask(() => port.attemptAsk(attempt.action_id))
      .then((done) => {
        if (done.value !== null && attempt.kind === 'invite') {
          const made = done.value as GrantCreateResult
          say(`Invitation ready for ${nameOf(made.grant.recipient_device_id)}. They accept it on their device.`)
        }
        return load()
      })
      .catch((error: unknown) => {
        say(failureMessage(error), 'danger')
      })
  }

  const grantRows = [...(grants?.grants ?? [])]
  // A revocation whose answer arrived after the command returned is listed from its record.
  const carriedOn: readonly Revoked[] = attempts
    .filter(
      (attempt) =>
        attempt.kind === 'revoke' &&
        attempt.phase === 'closed' &&
        attempt.outcome === 'happened' &&
        attempt.result !== null
    )
    .map((attempt) => ({
      grantId: attempt.grant_id ?? '',
      name: attempt.label,
      atMs: Number(attempt.composed_at_ms),
      pending: pendingWorkers(attempt.result as RevocationResult),
      action: attempt.action_id
    }))
  const owners = everyone.filter((device) => device.manages_host && !device.revoked)
  const visibleAttempts = attempts.filter(
    (attempt) =>
      !attempt.hidden &&
      !(attempt.phase === 'closed' && attempt.result !== null) &&
      (attempt.session_id === null || attempt.session_id === sessionId)
  )
  const openAttempts = attempts.filter(isOpen)

  if (handing !== null) {
    return (
      <>
        <h2>Sharing</h2>
        <Transfer
          sessionId={sessionId}
          subject={subject}
          giving={handing}
          givingName={nameOf(handing.grant.recipient_device_id)}
          devices={everyone}
          nowMs={now}
          onDone={() => {
            returnTo.current = null
            setHanding(null)
            focusNext.current = 'heading'
            void load()
          }}
          onClose={() => {
            setHanding(null)
          }}
        />
      </>
    )
  }

  return (
    <>
      <h2 id={headingId} ref={heading} tabIndex={-1}>
        Sharing
      </h2>
      <p className="muted">
        Share this session with a device paired with this host. An invitation is used once.
      </p>

      {failure !== null ? (
        <Banner
          tone="warning"
          title="Sharing could not be read"
          detail={failure}
          action={
            <Button
              onClick={() => {
                void load()
              }}
            >
              Try again
            </Button>
          }
        />
      ) : null}

      <section className="access" aria-labelledby={`${headingId}-access`} data-testid="access">
        <h3 id={`${headingId}-access`}>Who has access</h3>
        {grants !== null && grantRows.length === 0 && owners.length === 0 ? (
          <p className="small muted" data-testid="nobody">
            Nobody but you has this session.
          </p>
        ) : null}
        {grantRows.length > 0 || owners.length > 0 ? (
          <Card data-testid="issued-grants">
            <div className="card-body">
              {grantRows.map((summary) => {
                const rights: readonly ActionRight[] = summary.grant.actions
                const name = nameOf(summary.grant.recipient_device_id)
                const role_ = roleWords(roleOfRights(rights))
                return (
                  <div
                    className="divided-row access-row"
                    key={summary.grant.grant_id}
                    data-grant={summary.grant.grant_id}
                    data-state={summary.state}
                    tabIndex={-1}
                  >
                    <span className="spacer access-who">
                      <span className="access-name">{name}</span>
                      <span className="small faint">
                        {role_}
                        {summary.ends_at_ms !== null
                          ? ` · until ${momentWords(Number(summary.ends_at_ms), now)}`
                          : ''}
                      </span>
                    </span>
                    <Badge tone={summary.state === 'active' ? 'success' : 'neutral'}>
                      {stateWords(summary.state)}
                    </Badge>
                    <span className="access-actions">
                      {summary.state === 'pending' ? (
                        <Button
                          data-testid="withdraw"
                          onClick={() => {
                            revoke(summary, grantRows, true)
                          }}
                        >
                          Withdraw
                        </Button>
                      ) : null}
                      {summary.state === 'active' ? (
                        <>
                          <Button
                            data-testid="revoke"
                            onClick={() => {
                              revoke(summary, grantRows, false)
                            }}
                          >
                            Revoke
                          </Button>
                          {rights.includes('session.share') ? (
                            <Button
                              data-testid="hand-over-open"
                              onClick={() => {
                                returnTo.current = summary.grant.grant_id
                                setHanding(summary)
                              }}
                            >
                              Hand over control…
                            </Button>
                          ) : null}
                        </>
                      ) : null}
                    </span>
                    {summary.state === 'active' ? (
                      <span className="small muted access-note">
                        What they already saw stays with them.
                      </span>
                    ) : null}
                  </div>
                )
              })}
              {owners.map((device) => (
                <div className="divided-row access-row" key={device.device_id} data-owner="true">
                  <span className="spacer access-who">
                    <span className="access-name">{device.display_name}</span>
                    <span className="small faint">Owner device · always has access</span>
                  </span>
                </div>
              ))}
            </div>
          </Card>
        ) : null}
        {grantRows.length > 0 || owners.length > 0 ? (
          <p className="small muted" data-testid="access-note">
            A device paired as an owner, or with a pairing that opens every session, keeps its own
            access whatever is done to a share.
          </p>
        ) : null}

        {[...revoked, ...carriedOn].map((line) => (
          <p className="small access-revoked" key={line.grantId} data-testid="recently-revoked">
            <span>
              Revoked {line.name} at {momentWords(line.atMs, now)}.
              {line.pending > 0
                ? ` ${String(line.pending)} session worker${line.pending === 1 ? ' has' : 's have'} not confirmed yet.`
                : ''}
            </span>{' '}
            {line.pending > 0 ? (
              <Button
                data-testid="check-again"
                onClick={() => {
                  checkAgain(line)
                }}
              >
                Check again
              </Button>
            ) : null}
            {line.action !== undefined ? (
              <Button
                data-testid="revoked-dismiss"
                onClick={() => {
                  const action = line.action
                  if (action === undefined) return
                  void ask(() => port.attemptRemove(action)).then(load, () => undefined)
                }}
              >
                Dismiss
              </Button>
            ) : null}
          </p>
        ))}

        {visibleAttempts.map((attempt) => (
          <div
            className="attempt"
            key={attempt.action_id}
            data-testid="attempt"
            data-phase={attempt.phase}
            data-outcome={attempt.outcome ?? undefined}
            role="status"
          >
            <p className="small">{attemptWords(attempt, now)}</p>
            {attempt.refusal !== null ? <p className="small muted">The host said: {attempt.refusal}</p> : null}
            <p className="attempt-actions">
              {attempt.phase !== 'closed' || attempt.follow_up ? (
                <Button
                  data-testid="attempt-ask"
                  onClick={() => {
                    askHost(attempt)
                  }}
                >
                  Ask the host
                </Button>
              ) : null}
              {isOpen(attempt) ? (
                <Button
                  data-testid="attempt-hide"
                  onClick={() => {
                    void ask(() => port.attemptHide(attempt.action_id)).then(load, () => undefined)
                  }}
                >
                  Hide
                </Button>
              ) : (
                <Button
                  data-testid="attempt-remove"
                  onClick={() => {
                    void ask(() => port.attemptRemove(attempt.action_id)).then(load, (error: unknown) => {
                      say(failureMessage(error), 'danger')
                    })
                  }}
                >
                  Remove
                </Button>
              )}
            </p>
          </div>
        ))}
        {openAttempts.length > visibleAttempts.filter(isOpen).length ? (
          <p className="small muted" data-testid="hidden-attempts">
            {String(openAttempts.length - visibleAttempts.filter(isOpen).length)} hidden attempt
            {openAttempts.length - visibleAttempts.filter(isOpen).length === 1 ? '' : 's'} can still
            happen, and a second of the same kind waits for {openAttempts.length === 1 ? 'it' : 'them'}.
          </p>
        ) : null}
      </section>

      {changed !== null ? (
        <div className="screen-changed" role="alert" data-testid="screen-changed">
          <h3>The screen changed before the invitation was written</h3>
          <p className="small">
            The invitation carries these lines, not the ones you were shown. Withdraw it if that is
            not what you meant to share.
          </p>
          <pre className="screen-lines" tabIndex={0} aria-label="The lines the host kept">
            {changed.map(visibly).join('\n')}
          </pre>
          <Button
            onClick={() => {
              setChanged(null)
            }}
          >
            Dismiss
          </Button>
        </div>
      ) : null}

      <form
        className="share-form"
        data-testid="share-form"
        onSubmit={(event) => {
          event.preventDefault()
        }}
      >
        <h3>Share with a device</h3>

        <fieldset className="settings-group" data-testid="recipients">
          <legend>Who it is for</legend>
          {devices !== null && offered.length === 0 ? (
            <p className="small muted" data-testid="no-devices">
              {everyone.length === 0
                ? 'No device is paired with this host. Pair the device first, from that device.'
                : 'No paired device can be given this session. The reasons are below.'}
            </p>
          ) : null}
          {offered.map((device) => (
            <RecipientRow
              key={device.device_id}
              device={device}
              sessionId={sessionId}
              checked={recipient === device.device_id}
              nowMs={now}
              onChoose={() => {
                setRecipient(device.device_id)
              }}
            />
          ))}
          {notOffered.length > 0 ? (
            <ul className="small muted not-offered" data-testid="not-offered">
              {notOffered.map((device) => (
                <li key={device.device_id}>
                  <strong>{device.display_name}</strong> is not offered. {whyNot(device, now)}
                </li>
              ))}
            </ul>
          ) : null}
        </fieldset>

        <fieldset className="settings-group" data-testid="roles">
          <legend>What they can do</legend>
          {ROLES.map((each) => (
            <label className="choice-row choice-described" key={each.role}>
              <input
                type="radio"
                name={`role-${sessionId}`}
                value={each.role}
                checked={role === each.role}
                onChange={() => {
                  setRole(each.role)
                }}
              />
              <span>
                <span className="choice-title">{each.title}</span>
                <span className="small muted choice-line">{each.line}</span>
              </span>
            </label>
          ))}
        </fieldset>

        <div className="settings-row">
          <div>
            <h3>Let them watch the session live</h3>
            <p data-testid="live-explanation">
              {live
                ? 'They see the screen as it is when they open it, and what follows. A resize can bring earlier lines into view, and a program that switches screens can show older text. This preview shows neither.'
                : 'They will not see the terminal or a live stream. What else this role allows is listed below.'}
            </p>
            {previewFailure !== null ? (
              <p className="small warning-text" role="alert" data-testid="preview-failure">
                {previewFailure}
              </p>
            ) : null}
          </div>
          <Switch
            checked={live}
            label="Let them watch the session live"
            onChange={(next) => {
              setPreviewFailure(null)
              setLive(next)
            }}
          />
        </div>
        <div className="disclosure" data-open={live ? 'true' : 'false'}>
          <div inert={!live}>
            <div className="screen-preview" data-testid="screen-preview">
              {preview.state === 'ready' ? (
                <>
                  <pre
                    className="screen-lines"
                    tabIndex={0}
                    role="region"
                    aria-label={`Screen at ${new Date(preview.readAt).toLocaleTimeString()}, ${String(preview.lines.length)} lines`}
                  >
                    {preview.lines.map(visibly).join('\n')}
                  </pre>
                  {preview.truncated ? (
                    <p className="small warning-text" role="alert" data-testid="preview-cut">
                      This screen is larger than a preview shows, so you would not be shown all of
                      it. Make the session’s terminal smaller, or share without the live view.
                    </p>
                  ) : null}
                </>
              ) : (
                <pre className="screen-lines" aria-hidden="true">
                  {' '}
                </pre>
              )}
              <Button
                data-testid="preview-refresh"
                onClick={() => {
                  setPreviewTick((each) => each + 1)
                }}
              >
                Refresh
              </Button>
            </div>
          </div>
        </div>

        <div className="settings-row">
          <div>
            <h3>Earlier activity</h3>
            <p>
              {live
                ? 'The agent’s conversation, questions and events from before. Never the terminal’s scrollback.'
                : 'The agent’s conversation and questions from before.'}{' '}
              None means from the moment you invite.
            </p>
          </div>
          <label className="visually-hidden-label">
            <span className="visually-hidden">Earlier activity</span>
            <select
              className="select"
              value={history}
              data-testid="history"
              onChange={(event) => {
                setHistory(event.target.value)
              }}
            >
              {HISTORY_CHOICES.map((each) => (
                <option key={each.key} value={each.key}>
                  {each.label}
                </option>
              ))}
            </select>
          </label>
        </div>

        <div className="settings-row">
          <div>
            <h3>Let them answer the agent’s questions</h3>
            <p data-testid="answering-explanation">
              Any answer, including free text, is input the agent may act on under your host’s
              permissions. A form does not reduce that. This is the same authority as an
              unrestricted prompt or terminal control.
            </p>
          </div>
          <Switch
            checked={role !== 'viewer' || answering}
            disabled={role !== 'viewer'}
            label="Let a viewer answer questions"
            onChange={setAnswering}
          />
        </div>

        <div className="settings-row">
          <div>
            <h3>Lasts</h3>
            <p data-testid="lasts-note">
              {chosen === null
                ? 'Choose a device first.'
                : pairingEnd(chosen) === null
                  ? 'Used once, and it ends when the time is up.'
                  : `This device’s pairing ends ${momentWords(pairingEnd(chosen) ?? now, now)} (in ${spanWords((pairingEnd(chosen) ?? now) - now)}). A share cannot outlast it.`}
            </p>
          </div>
          <label className="visually-hidden-label">
            <span className="visually-hidden">How long the invitation lasts</span>
            <select
              className="select"
              value={effective?.key ?? ''}
              disabled={options.length === 0}
              data-testid="lasts"
              onChange={(event) => {
                setLasting(event.target.value)
              }}
            >
              {options.map((each) => (
                <option key={each.key} value={each.key}>
                  {each.label}
                </option>
              ))}
            </select>
          </label>
        </div>

        <div className="invitation-carries">
          <Card data-testid="invitation-carries">
            <div className="card-body">
              <h3>This invitation carries</h3>
              <ul className="consequence-list">
                {(shown?.actions ?? []).map((action) => (
                  <li key={action}>{actionWords(action)}</li>
                ))}
              </ul>
              <p className="small muted invitation-notice" data-testid="no-current-screen">
                {live
                  ? 'The live view is included, as the preview above shows it.'
                  : 'It does not include what is on the screen now.'}{' '}
                {chosen !== null && effective !== null
                  ? `It starts ${
                      history === 'none' ? 'from the moment you invite' : 'at the earlier activity you chose'
                    } and ends ${momentWords(
                      now + lifetimeMs(effective, chosen, now),
                      now
                    )}. Used once.`
                  : ''}
              </p>
              {(shown?.notices ?? []).map((each) => (
                <p
                  className="small warning-text invitation-notice"
                  key={each.notice}
                  data-notice={each.notice}
                >
                  {each.sentence}
                </p>
              ))}
            </div>
          </Card>
        </div>

        <div className="disclosure" data-open={carries ? 'true' : 'false'}>
          <div inert={!carries}>
            <label className="choice-row consent" data-testid="consent">
              <input
                type="checkbox"
                checked={consented}
                onChange={(event) => {
                  setConsentFor(event.target.checked ? consentKey : null)
                }}
              />
              <span>
                I understand this lets {chosen?.display_name ?? 'the device'} do what the
                consequences above say
                {geometry ? ', and resize the terminal' : ''}.
              </span>
            </label>
          </div>
        </div>

        <div className="sharing-invite">
          <CommitButton data-testid="invite" disabled={!ready} onCommit={issue}>
            {chosen === null ? 'Choose a device to invite' : `Invite ${chosen.display_name}`}
          </CommitButton>
        </div>
      </form>
    </>
  )
}

/** One paired device an invitation can go to. */
function RecipientRow({
  device,
  sessionId,
  checked,
  nowMs,
  onChoose
}: {
  readonly device: DeviceSummary
  readonly sessionId: string
  readonly checked: boolean
  readonly nowMs: number
  readonly onChoose: () => void
}): ReactNode {
  const end = pairingEnd(device)
  return (
    <label className="choice-row">
      <input
        type="radio"
        name={`recipient-${sessionId}`}
        value={device.device_id}
        checked={checked}
        onChange={onChoose}
      />
      <span>
        {device.display_name}
        <span className="small faint">
          {' '}
          · {platformWords(device.platform)} · paired{' '}
          {new Date(Number(device.paired_at_ms)).toLocaleDateString()}
          {end === null ? '' : ` · pairing ends in ${spanWords(end - nowMs)}`}
        </span>
      </span>
    </label>
  )
}
