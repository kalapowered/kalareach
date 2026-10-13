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
 *
 * The host's result for an action reaches this screen by three roads: the command that sent it, a
 * repeat native code made in the background, and the person asking the host. All three end in the
 * same place (`receive`), so what the person is told and what the screen keeps never depends on
 * which road it came by.
 */

import {
  useCallback,
  useEffect,
  useId,
  useRef,
  useState,
  useSyncExternalStore,
  type ReactNode
} from 'react'

import type {
  ActionRight,
  DeviceListResult,
  DeviceSummary,
  GrantCreateResult,
  GrantListResult,
  GrantSummary,
  GrantTransferResult,
  RevocationResult,
  RoleSelection
} from '@kalareach/protocol'

import { Badge, Banner, Button, Card, CommitButton, Switch } from '../components/ui'
import { useApp } from '../app/state'
import {
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
  failureText,
  historyFrom,
  isOpen,
  lastings,
  lifetimeMs,
  momentWords,
  nameWords,
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
import { deskOf } from '../model/sharing-desk'
import { handedOver, invited, pendingWorkers, rechecked, tookBack } from '../model/sharing-results'
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

/**
 * Sharing, over one session. A new session is a new screen: nothing the form held, no choice and
 * no tick, carries over to the next.
 */
export function Sharing(props: {
  readonly sessionId: string
  readonly subject: SessionSubject
}): ReactNode {
  return <SharingTab key={props.sessionId} {...props} />
}

function SharingTab({
  sessionId,
  subject
}: {
  readonly sessionId: string
  readonly subject: SessionSubject
}): ReactNode {
  const { port, say } = useApp()
  const desk = deskOf(port)
  const kept = useSyncExternalStore(desk.subscribe, desk.snapshot)
  const revoked = kept.revoked
  const notes = kept.notes.filter((each) => each.sessionId === sessionId)
  const [devices, setDevices] = useState<DeviceListResult | null>(null)
  const [grants, setGrants] = useState<GrantListResult | null>(null)
  const [attempts, setAttempts] = useState<readonly AttemptView[]>([])
  const [unreadable, setUnreadable] = useState(0)
  const [failure, setFailure] = useState<string | null>(null)
  const [now, setNow] = useState(() => clock.now())
  const [handing, setHanding] = useState<GrantSummary | null>(null)
  const reads = useRef<Watch | null>(null)
  const headingId = useId()
  const heading = useRef<HTMLHeadingElement | null>(null)
  const focusNext = useRef<string | null>(null)
  const focusAttempt = useRef<string | null>(null)
  const returnTo = useRef<string | null>(null)

  // The form.
  const [recipient, setRecipient] = useState<string | null>(null)
  const [role, setRole] = useState<OfferedRole>('viewer')
  const [live, setLive] = useState(false)
  const [history, setHistory] = useState('none')
  const [answering, setAnswering] = useState(false)
  const [lasting, setLasting] = useState<string | null>(null)
  // Consent belongs to the choices as they stand. Every change of a choice is a new count, so a
  // change and its undoing are two changes, and a tick given to the first is not given to the other.
  const [choices, setChoices] = useState(0)
  const [consentAt, setConsentAt] = useState<string | null>(null)
  const [previewFailure, setPreviewFailure] = useState<string | null>(null)
  const [issuing, setIssuing] = useState(false)
  const [notices, setNotices] = useState<{
    readonly key: string
    readonly notices: GrantNotices
  } | null>(null)

  /** Changes a choice of the form, and with it what the person has agreed to. */
  const choose = (apply: () => void) => {
    apply()
    setChoices((each) => each + 1)
  }

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
      .then(([paired, issued, listed]) => {
        if (!current()) return
        setDevices(paired)
        setGrants(issued)
        setAttempts(listed.attempts)
        setUnreadable(listed.unreadable)
        setNow(clock.now())
        setFailure(null)
      })
      .catch((error: unknown) => {
        if (!current()) return
        setFailure(failureText(error))
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
        if (current) setFailure(failureText(error))
      })
    return () => {
      current = false
    }
  }, [port, role, answering, noticeKey])

  const shown = notices?.key === noticeKey ? notices.notices : null
  const everyone = devices?.devices ?? []
  const names = new Map(everyone.map((device) => [device.device_id, device.display_name]))
  const nameOf = (id: string | null): string => (id === null ? undefined : names.get(id)) ?? 'A paired device'
  /** Whether an attempt is about this session, or about no session in particular. */
  const here = (attempt: AttemptView) => attempt.session_id === null || attempt.session_id === sessionId

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
          choose(() => {
            setLive(false)
          })
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
        choose(() => {
          setLive(false)
        })
        setPreviewFailure(failureText(error))
      })
    return () => {
      current = false
    }
  }, [port, sessionId, live, history, role, answering, previewKey])

  const consentKey = `${String(choices)}|${effective?.key ?? ''}`
  const consented = consentAt === consentKey
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

  // After an attempt is hidden, to the control that shows it again; after it is shown, to the attempt.
  useEffect(() => {
    const wanted = focusAttempt.current
    if (wanted === null) return
    const [what, action] = [wanted.slice(0, wanted.indexOf(':')), wanted.slice(wanted.indexOf(':') + 1)]
    const target = document.querySelector<HTMLElement>(
      what === 'show' ? `[data-show="${action}"]` : `[data-attempt="${action}"]`
    )
    if (target === null) return
    focusAttempt.current = null
    target.focus()
  }, [attempts])

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

  // ---- What the host's result for an attempt is told as, whichever road it came by --------------

  /**
   * The host's result for an attempt, in hand by the command that sent it, by a repeat native code
   * made in the background, or by the person asking the host. The first delivery is told and kept
   * on the desk, which outlives this screen; a second, by another road, changes nothing.
   */
  const receive = (attempt: AttemptView, value: unknown): boolean => {
    if (!desk.firstTime(attempt.action_id)) return false
    if (attempt.kind === 'invite') {
      const made = value as GrantCreateResult
      invited(desk, say, made, nameOf(made.grant.recipient_device_id), desk.recall(attempt.action_id))
    } else if (attempt.kind === 'revoke') {
      const grantId = attempt.revoked_grant_id ?? attempt.grant_id ?? ''
      if (desk.isCheck(attempt.action_id)) {
        // The answer to a Check again whose reply was lost. It changes how far the workers have
        // got on the line that is there, and never makes a line: one the person dismissed since
        // stays dismissed.
        if (desk.has(grantId)) recheck(value as RevocationResult, grantId)
      } else {
        const meant = desk.meant(grantId)
        tookBack(
          desk,
          say,
          value as RevocationResult,
          grantId,
          meant?.name ?? 'a paired device',
          meant?.withdrawing ?? false,
          clock.now()
        )
      }
    } else if (attempt.kind === 'transfer') {
      const done = value as GrantTransferResult
      const words = `${nameWords(attempt.label)}: done.`
      if (attempt.revoked_grant_id === null) say(words)
      else {
        handedOver(desk, say, done, attempt.revoked_grant_id, 'the device that gave control up', words, clock.now())
      }
    }
    return true
  }

  /**
   * Says how far the workers have got with a revocation already on the page. A button that is on
   * that line and goes when nothing is pending gives its focus to the line first.
   */
  function recheck(result: RevocationResult, grantId: string): void {
    if (pendingWorkers(result) === 0) {
      const line = document.querySelector<HTMLElement>(`[data-line="${grantId}"]`)
      if (line !== null && line.contains(document.activeElement) && document.activeElement !== line) {
        line.focus()
      }
    }
    rechecked(desk, result, grantId)
  }

  // What the latest render knows, for the callbacks that outlive a render.
  const latest = useRef({ receive })
  useEffect(() => {
    latest.current = { receive }
  })

  // An attempt that was carried on after the command that sent it returned, and ended with the
  // host's result, is told once as the success the command would have been, where it belongs: an
  // invitation or a hand-over of another session waits for that session's tab. Its record then has
  // no further use, and goes.
  useEffect(() => {
    for (const attempt of attempts) {
      if (attempt.phase !== 'closed' || attempt.outcome !== 'happened') continue
      if (attempt.result === null || !here(attempt)) continue
      // Only the delivery that took the result in removes the record, once: a record that stays
      // is not asked to go at every reading of the list.
      if (!latest.current.receive(attempt, attempt.result)) continue
      void ask(() => port.attemptRemove(attempt.action_id)).then(load, (error: unknown) => {
        // Told once, and not told again each time the attempts are read: the record stays, and a
        // restart lists it with what the host can still be asked for.
        say(failureText(error), 'danger')
      })
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps -- `here` and `receive` read the latest render
  }, [attempts, port, load, say])

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
        // The lines the person was shown are kept for the answer, by whichever road it arrives.
        if (shownLines !== null) desk.remember(done.attempt.action_id, shownLines)
        if (done.attempt.phase !== 'closed' || done.value === null) {
          say(
            `The host’s answer did not arrive. The invitation to ${nameWords(chosen.display_name)} is listed as unfinished; ask the host about it.`,
            'pending'
          )
        } else {
          focusNext.current = done.value.grant.grant_id
          receive(done.attempt, done.value)
          setConsentAt(null)
        }
        return load()
      })
      .catch((error: unknown) => {
        say(failureText(error), 'danger')
      })
      .finally(() => {
        setIssuing(false)
      })
  }

  /**
   * Gives focus to the row beside the one a control is about to take away, or to the heading when
   * there is none, so that it never falls to the page behind the sheet. Returns what moves it,
   * for a control whose row goes only when the host says so. A control that withdraws a grant
   * names it, and the grant's own row, which the withdrawal takes away too, is not a place to go.
   */
  const awayFrom = (control: HTMLElement | null, withdrawn?: string): (() => void) => {
    const rowsNow = (): HTMLElement[] =>
      Array.from(
        (heading.current?.parentElement ?? document).querySelectorAll<HTMLElement>('[data-nav]')
      ).filter((row) => withdrawn === undefined || row.dataset.grant !== withdrawn)
    const own = control?.closest<HTMLElement>('[data-nav]') ?? null
    const was = own === null ? -1 : rowsNow().indexOf(own)
    return () => {
      // Looked for when focus is to move, not when the control was pressed: a row the person
      // dismissed while the host was answering is not a place to go.
      const rows = rowsNow()
      const at = own !== null && rows.includes(own) ? rows.indexOf(own) : -1
      const next =
        at >= 0 ? (rows[at + 1] ?? rows[at - 1]) : (rows[Math.max(was, 0)] ?? rows[rows.length - 1])
      ;(next ?? heading.current)?.focus()
    }
  }

  /** Takes a share back or withdraws an invitation, and tells what the host said. */
  const takeBack = (grantId: string, name: string, withdrawing: boolean, after?: () => void) => {
    desk.intend(grantId, { name, withdrawing })
    ask(() => port.grantRevoke({ grant_id: grantId }))
      .then((done) => {
        if (done.value === null) {
          say(
            `The host’s answer did not arrive. The ${withdrawing ? 'withdrawal' : 'revocation'} is listed as unfinished; ask the host about it.`,
            'pending'
          )
          return load()
        }
        if (desk.firstTime(done.attempt.action_id)) {
          tookBack(desk, say, done.value, grantId, name, withdrawing, clock.now())
        }
        after?.()
        return load()
      })
      .catch((error: unknown) => {
        say(failureText(error), 'danger')
      })
  }

  const revoke = (summary: GrantSummary, rows: readonly GrantSummary[], withdrawing: boolean) => {
    const index = rows.findIndex((each) => each.grant.grant_id === summary.grant.grant_id)
    const next = rows[index + 1] ?? rows[index - 1]
    focusNext.current = next === undefined ? 'heading' : next.grant.grant_id
    takeBack(summary.grant.grant_id, nameOf(summary.grant.recipient_device_id), withdrawing)
  }

  const checkAgain = (grantId: string) => {
    ask(() => port.grantRevoke({ grant_id: grantId }))
      .then((done) => {
        // Whatever comes of it, this action is a check: its answer, if it arrives later, is only
        // ever an answer to one.
        desk.markCheck(done.attempt.action_id)
        if (done.value === null) {
          say('The host’s answer did not arrive. Check again in a moment.', 'pending')
          return
        }
        if (desk.firstTime(done.attempt.action_id) && desk.has(grantId)) recheck(done.value, grantId)
      })
      .catch((error: unknown) => {
        say(failureText(error), 'danger')
      })
  }

  const askHost = (attempt: AttemptView, away: () => void) => {
    ask(() => port.attemptAsk(attempt.action_id))
      .then((done) => {
        if (done.value === null) {
          say('The host did not say what became of it. Ask again in a moment.', 'pending')
        } else {
          receive(attempt, done.value)
          away()
        }
        return load()
      })
      .catch((error: unknown) => {
        say(failureText(error), 'danger')
      })
  }

  const setHidden = (attempt: AttemptView, hidden: boolean) => {
    focusAttempt.current = `${hidden ? 'show' : 'attempt'}:${attempt.action_id}`
    void ask(() => port.attemptSetHidden(attempt.action_id, hidden)).then(load, (error: unknown) => {
      focusAttempt.current = null
      say(failureText(error), 'danger')
    })
  }

  const removeAttempt = (attempt: AttemptView, away: () => void) => {
    away()
    void ask(() => port.attemptRemove(attempt.action_id)).then(load, (error: unknown) => {
      say(failureText(error), 'danger')
    })
  }

  const grantRows = [...(grants?.grants ?? [])]
  const owners = everyone.filter((device) => device.manages_host && !device.revoked)
  const visibleAttempts = attempts.filter(
    (attempt) =>
      !attempt.hidden && !(attempt.phase === 'closed' && attempt.result !== null) && here(attempt)
  )
  const hiddenAttempts = attempts.filter((attempt) => attempt.hidden && isOpen(attempt) && here(attempt))

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
          onDone={(_receiver, replacementGrantId) => {
            returnTo.current = null
            setHanding(null)
            // The person is taken to the row of the device that now holds the session.
            focusNext.current = replacementGrantId ?? 'heading'
            void load()
          }}
          onClose={() => {
            setHanding(null)
            // What the panel left behind, if anything, is on the list at once.
            void load()
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
                const name = nameWords(nameOf(summary.grant.recipient_device_id))
                const role_ = roleWords(roleOfRights(rights))
                return (
                  <div
                    className="divided-row access-row"
                    key={summary.grant.grant_id}
                    data-grant={summary.grant.grant_id}
                    data-nav
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
                    <span className="access-name">{nameWords(device.display_name)}</span>
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

        {revoked.map((line) => (
          <p
            className="small access-revoked"
            key={line.grantId}
            data-testid="recently-revoked"
            data-line={line.grantId}
            data-nav
            tabIndex={-1}
          >
            <span>
              Revoked {nameWords(line.name)} at {momentWords(line.atMs, now)}.
              {line.pending > 0
                ? ` ${String(line.pending)} session worker${line.pending === 1 ? ' has' : 's have'} not confirmed yet.`
                : ''}
            </span>{' '}
            {line.pending > 0 ? (
              <Button
                data-testid="check-again"
                onClick={() => {
                  checkAgain(line.grantId)
                }}
              >
                Check again
              </Button>
            ) : null}
            <Button
              data-testid="revoked-dismiss"
              onClick={(event) => {
                awayFrom(event.currentTarget)()
                desk.dismissRevocation(line.grantId)
              }}
            >
              Dismiss
            </Button>
          </p>
        ))}

        {visibleAttempts.map((attempt) => (
          <div
            className="attempt"
            key={attempt.action_id}
            data-testid="attempt"
            data-attempt={attempt.action_id}
            data-nav
            data-phase={attempt.phase}
            data-outcome={attempt.outcome ?? undefined}
            role="status"
            tabIndex={-1}
          >
            <p className="small">{attemptWords(attempt, now)}</p>
            {attempt.refusal !== null ? (
              <p className="small muted">The host said: {visibly(attempt.refusal)}</p>
            ) : null}
            {attempt.kind === 'invite' && attempt.phase === 'closed' && attempt.follow_up ? (
              <p className="small" data-testid="attempt-unverified">
                The host kept a screen with this invitation, and it could not be compared with the
                one you were shown. Ask the host for it, or withdraw the invitation.
              </p>
            ) : null}
            <p className="attempt-actions">
              {attempt.phase === 'asking' ? (
                <Button
                  data-testid="attempt-cancel"
                  onClick={(event) => {
                    removeAttempt(attempt, awayFrom(event.currentTarget))
                  }}
                >
                  Cancel
                </Button>
              ) : (
                <>
                  {attempt.phase !== 'closed' || attempt.follow_up ? (
                    <Button
                      data-testid="attempt-ask"
                      onClick={(event) => {
                        askHost(attempt, awayFrom(event.currentTarget))
                      }}
                    >
                      Ask the host
                    </Button>
                  ) : null}
                  {attempt.kind === 'invite' &&
                  attempt.phase === 'closed' &&
                  attempt.follow_up &&
                  attempt.grant_id !== null ? (
                    <Button
                      data-testid="attempt-withdraw"
                      onClick={(event) => {
                        const grantId = attempt.grant_id
                        if (grantId === null) return
                        const away = awayFrom(event.currentTarget, grantId)
                        takeBack(grantId, nameOf(attempt.device_id), true, () => {
                          removeAttempt(attempt, away)
                        })
                      }}
                    >
                      Withdraw
                    </Button>
                  ) : null}
                  {isOpen(attempt) ? (
                    <Button
                      data-testid="attempt-hide"
                      onClick={() => {
                        setHidden(attempt, true)
                      }}
                    >
                      Hide
                    </Button>
                  ) : (
                    <Button
                      data-testid="attempt-remove"
                      onClick={(event) => {
                        removeAttempt(attempt, awayFrom(event.currentTarget))
                      }}
                    >
                      Remove
                    </Button>
                  )}
                </>
              )}
            </p>
          </div>
        ))}
        {hiddenAttempts.length > 0 ? (
          <div className="small muted hidden-attempts" data-testid="hidden-attempts">
            <p>
              {String(hiddenAttempts.length)} hidden attempt
              {hiddenAttempts.length === 1 ? '' : 's'} can still happen, and a second of the same kind
              waits for {hiddenAttempts.length === 1 ? 'it' : 'them'}.
            </p>
            <ul>
              {hiddenAttempts.map((attempt) => (
                <li key={attempt.action_id}>
                  <span>{nameWords(attempt.label)}</span>
                  <Button
                    data-testid="attempt-show"
                    data-show={attempt.action_id}
                    onClick={() => {
                      setHidden(attempt, false)
                    }}
                  >
                    Show
                  </Button>
                </li>
              ))}
            </ul>
          </div>
        ) : null}
        {unreadable > 0 ? (
          <p className="small muted" data-testid="attempts-unreadable">
            {String(unreadable)} record{unreadable === 1 ? '' : 's'} of sharing on this device{' '}
            {unreadable === 1 ? 'is' : 'are'} not read by this version, and{' '}
            {unreadable === 1 ? 'is' : 'are'} left as {unreadable === 1 ? 'it is' : 'they are'}.
          </p>
        ) : null}
      </section>

      {notes.map((each) => (
        <div
          className="screen-changed"
          role="alert"
          key={each.grantId}
          data-testid="screen-changed"
          data-kind={each.kind}
          data-nav
          tabIndex={-1}
        >
          <h3>
            {each.kind === 'changed'
              ? 'The screen changed before the invitation was written'
              : 'The screen could not be compared'}
          </h3>
          <p className="small">
            {each.kind === 'changed'
              ? `The invitation to ${nameWords(each.name)} carries these lines, not the ones you were shown. Withdraw it if that is not what you meant to share.`
              : `The invitation to ${nameWords(each.name)} carries these lines. The ones you were shown are no longer here to compare them with. Withdraw it if that is not what you meant to share.`}
          </p>
          <pre className="screen-lines" tabIndex={0} aria-label="The lines the host kept">
            {each.lines.map(visibly).join('\n')}
          </pre>
          <p className="attempt-actions">
            <Button
              data-testid="screen-withdraw"
              onClick={(event) => {
                const away = awayFrom(event.currentTarget, each.grantId)
                takeBack(each.grantId, each.name, true, away)
              }}
            >
              Withdraw
            </Button>
            <Button
              data-testid="screen-dismiss"
              onClick={(event) => {
                awayFrom(event.currentTarget)()
                desk.dismissNote(each.grantId)
              }}
            >
              Dismiss
            </Button>
          </p>
        </div>
      ))}

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
                choose(() => {
                  setRecipient(device.device_id)
                })
              }}
            />
          ))}
          {notOffered.length > 0 ? (
            <ul className="small muted not-offered" data-testid="not-offered">
              {notOffered.map((device) => (
                <li key={device.device_id}>
                  <strong>{nameWords(device.display_name)}</strong> is not offered. {whyNot(device, now)}
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
                  choose(() => {
                    setRole(each.role)
                  })
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
              choose(() => {
                setLive(next)
              })
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
                choose(() => {
                  setHistory(event.target.value)
                })
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
            onChange={(next) => {
              choose(() => {
                setAnswering(next)
              })
            }}
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
                choose(() => {
                  setLasting(event.target.value)
                })
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
                  setConsentAt(event.target.checked ? consentKey : null)
                }}
              />
              <span>
                I understand this lets {nameWords(chosen?.display_name ?? 'the device')} do what the
                consequences above say
                {geometry ? ', and resize the terminal' : ''}.
              </span>
            </label>
          </div>
        </div>

        <div className="sharing-invite">
          <CommitButton data-testid="invite" disabled={!ready} onCommit={issue}>
            {chosen === null ? 'Choose a device to invite' : `Invite ${nameWords(chosen.display_name)}`}
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
        {nameWords(device.display_name)}
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
