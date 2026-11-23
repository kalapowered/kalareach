/**
 * The attention inbox.
 *
 * Four states, kept apart on purpose, and one more beside them. A pending decision is something
 * waiting for the person, and an approval among them is answered here, from what the agent's own
 * worker says it offered. A failed action is something that finished badly and says why. Completed
 * work awaiting review is finished and fine. A disconnected host is none of those: it is the absence
 * of contact, and the one thing this screen must never do is turn silence into a claim that an agent
 * is stuck. A notice an application printed is shown for what it is: not the host's, and never a
 * decision.
 */

import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react'

import type { AttentionReadResult } from '@kalareach/protocol'

import { Badge, Banner, Button, Card } from '../components/ui'
import { readOnCadence } from '../app/cadence'
import { useApp } from '../app/state'
import {
  failureCode,
  failureMessage,
  holdsFor,
  keyOfState,
  READ_SUPERSEDED,
  sameKey,
  watch,
  type ConnectionState,
  type ReadKey,
  type Watch
} from '../host/port'
import { ask } from '../mobile/model/call'
import {
  ATTENTION_READ_CADENCE_MS,
  contactWords,
  describeElapsed,
  emptyMessage,
  filter as filtered,
  inboxNotes,
  KIND_LABEL,
  order,
  readWholeInbox,
  THIS_COMPUTER,
  type AttentionFilter,
  type AttentionRow
} from '../model/attention'
import { outcomeMessage, outcomeTone } from '../model/receipts'
import { Confirmations } from '../pairing/Confirmations'
import { ApprovalRequests } from './Approvals'
import { KeptAnswers, QuestionRequests } from './Questions'

const FILTERS: readonly { readonly value: AttentionFilter; readonly label: string }[] = [
  { value: 'all', label: 'Everything' },
  { value: 'pending_decision', label: 'Decisions' },
  { value: 'failed_action', label: 'Failures' },
  { value: 'awaiting_review', label: 'To review' },
  { value: 'disconnected', label: 'Out of contact' },
  { value: 'notice', label: 'Notices' }
]

/** How a row's tone reads as a badge. */
const BADGE_TONE = {
  warning: 'warning',
  danger: 'danger',
  success: 'success',
  muted: 'neutral'
} as const

/** Whether an inbox row is a question waiting for an answer. */
function asksAQuestion(row: AttentionRow): boolean {
  return (
    row.item.rule === 'attention.pending_input' ||
    row.item.rule === 'attention.input_idle_reminder'
  )
}

/** The largest page of the inbox one read asks for. */
const PAGE_ITEMS = '200'

const NO_NUMBERS: ReadonlyMap<string, string> = new Map()

/**
 * The inbox. `latest` is the connection's latest state, which the row of contact is drawn from and
 * which decides what of a cache is shown: null until the connection has said anything.
 */
export function Attention({ latest }: { readonly latest: ConnectionState | null }): ReactNode {
  const { port, go, say } = useApp()
  // What the host in use said, under the key the owner said it holds under: a read is stored only
  // while that is the key of the connection's latest state, and shown while the host and its epoch
  // still hold. A read that fails leaves it as it is, and a host that refused moved its epoch.
  const [inbox, setInbox] = useState<{
    readonly key: ReadKey
    readonly result: AttentionReadResult
    readonly atMs: number
  } | null>(null)
  const [failure, setFailure] = useState<string | null>(null)
  const [chosen, setChosen] = useState<AttentionFilter>('all')
  // Each session's display number, by its identifier, as the host in use listed them, under a key of
  // their own: a failed or differently keyed read of them leaves the inbox as it is.
  const [numbers, setNumbers] = useState<{
    readonly key: ReadKey
    readonly named: ReadonlyMap<string, string>
  } | null>(null)
  const [nowMs, setNowMs] = useState(() => Date.now())
  // Every read of the inbox, on opening, on the cadence, after an answer and on a retry, goes
  // through one cadence under one watch with no listeners: one read at a time, only the newest
  // read's answer shown, and none once the screen closes.
  const reads = useRef<Watch | null>(null)
  const again = useRef<() => void>(() => undefined)

  // One read of the inbox and of the numbers. What it read is kept only under the key of the
  // connection's latest state at the moment it completes: the answer's own key is the owner's, and the
  // page gives no read an authority of its own. A dropped read (superseded, or under another key) says
  // so, and the next read waits for the cadence, a connection change or one more attempt.
  const readOnce = useCallback(
    (current: () => boolean): Promise<boolean> => {
      const inboxRead = ask(() =>
        readWholeInbox((after) =>
          port.attentionRead({
            session_id: null,
            include_acknowledged: false,
            max_items: PAGE_ITEMS,
            after
          })
        )
      ).then(
        (answer) => {
          if (!current()) return false
          const now = port.connectionLatest()
          if (now === null || !sameKey(answer.key, keyOfState(now))) return true
          setInbox({ key: answer.key, result: answer.value, atMs: Date.now() })
          setFailure(null)
          return false
        },
        (error: unknown) => {
          if (!current()) return false
          if (failureCode(error) === READ_SUPERSEDED) return true
          setFailure(failureMessage(error))
          return false
        }
      )
      // Only for the words: an inbox read without them names a session by nothing but the item. A read
      // of them that fails, or is dropped, clears the numbers that were kept, so the rows say "A
      // session" and never a number from an earlier read; a drop is a drop like the inbox's.
      const numbersRead = ask(() => port.sessionNumbers()).then(
        (answer) => {
          if (!current()) return false
          const now = port.connectionLatest()
          if (now === null || !sameKey(answer.key, keyOfState(now))) {
            setNumbers(null)
            return true
          }
          setNumbers({
            key: answer.key,
            named: new Map(
              answer.value.sessions.map((session) => [session.session_id, session.display_number])
            )
          })
          return false
        },
        (error: unknown) => {
          if (!current()) return false
          setNumbers(null)
          return failureCode(error) === READ_SUPERSEDED
        }
      )
      return Promise.all([inboxRead, numbersRead]).then(
        ([inboxDropped, numbersDropped]) => inboxDropped || numbersDropped
      )
    },
    [port]
  )

  const load = useCallback(
    async (takeAskedFor: () => void): Promise<void> => {
      const current = reads.current?.read() ?? null
      if (current === null) return
      // A read that is dropped makes one new read from the connection's state as it stands then, and
      // that read is the one a change of connection asked for meanwhile; a second one that is dropped
      // waits for the cadence or for a change that comes after.
      if (await readOnce(current)) {
        takeAskedFor()
        await readOnce(current)
      }
      if (current()) setNowMs(Date.now())
    },
    [readOnce]
  )

  // The inbox is read once the connection listener is registered, so no change of connection falls
  // between the read and it, and read again on the cadence and on each change of connection.
  useEffect(() => {
    const cadence = readOnCadence(load, ATTENTION_READ_CADENCE_MS)
    const reading = watch([port.onConnection(cadence.now)], cadence.now, (error) => {
      setFailure(failureMessage(error))
    })
    reads.current = reading
    again.current = cadence.now
    return () => {
      cadence.stop()
      reading.stop()
      if (reads.current === reading) reads.current = null
      again.current = () => undefined
    }
  }, [port, load])

  const readAgain = useCallback(() => {
    again.current()
  }, [])

  const acknowledge = (row: AttentionRow) => {
    ask(() =>
      port.attentionAcknowledge({ items: [{ key: row.item.key, revision: row.item.revision }] })
    )
      .then((settled) => {
        const stale = settled.value?.stale.includes(row.item.key) ?? false
        say(
          stale
            ? 'That changed since you saw it, so it was not marked. It is shown as it is now.'
            : outcomeMessage('Marked as seen', settled),
          stale ? 'pending' : outcomeTone(settled)
        )
        readAgain()
      })
      .catch((error: unknown) => {
        say(failureMessage(error), 'danger')
      })
  }

  // The host in use's rows are those read under the host and epoch the connection holds now. A
  // refusal moves the epoch, so a host that refused shows none.
  const here = inbox !== null && latest !== null && holdsFor(inbox.key, latest) ? inbox : null
  const numbered: ReadonlyMap<string, string> =
    numbers !== null && latest !== null && holdsFor(numbers.key, latest) ? numbers.named : NO_NUMBERS
  const rows = here ? filtered(order(here.result, here.atMs), chosen) : []
  const notes = here ? inboxNotes(here.result) : []

  // A host in use that does not answer has a row of contact, from the connection's state: the host
  // on this computer is named by the shared title. A host never reached, and one that answered and
  // refused, are not out of contact.
  const lost = useMemo(() => {
    if (latest === null || latest.host === null || latest.contact.state !== 'out_of_contact') return null
    return {
      name: latest.host.kind === 'local' ? THIS_COMPUTER : latest.host.name,
      sinceMs: latest.contact.since_ms,
      escalatesAtMs: latest.contact.escalates_at_ms
    }
  }, [latest])
  const escalatesAtMs = lost?.escalatesAtMs ?? null
  const urgent = escalatesAtMs !== null && nowMs >= escalatesAtMs

  // The level a loss has reached moves at the instant its state says, whatever the reads do. A state
  // that arrives after its instant has its timer run at once, so the clock is never behind it.
  useEffect(() => {
    if (escalatesAtMs === null) return undefined
    const wait = Math.max(0, escalatesAtMs - Date.now())
    const timer = setTimeout(() => {
      setNowMs(Date.now())
    }, wait)
    return () => {
      clearTimeout(timer)
    }
  }, [escalatesAtMs])

  const showContact = lost !== null && (chosen === 'all' || chosen === 'disconnected')
  // A session's approvals are listed once, under its first approval item, whatever number of items
  // the host raised for them.
  const approvalsShown = new Set<string>()
  const questionsShown = new Set<string>()

  return (
    <>
      <header className="page-heading">
        <div>
          <p className="eyebrow">Attention</p>
          <h1>What needs you</h1>
          <p>Decisions, failures and finished work, across every host you have paired.</p>
        </div>
      </header>

      <Confirmations />

      <KeptAnswers />

      {failure && lost === null ? (
        <Banner
          tone="warning"
          title="This list could not be read"
          detail={failure}
          action={<Button onClick={readAgain}>Try again</Button>}
        />
      ) : null}

      {notes.length > 0 ? (
        <ul className="inbox-notes" data-testid="inbox-notes">
          {notes.map((note) => (
            <li key={note} className="small muted">
              {note}
            </li>
          ))}
        </ul>
      ) : null}

      <div className="toolbar">
        <div className="filters" role="group" aria-label="Filter the inbox">
          {FILTERS.map((option) => (
            <button
              key={option.value}
              type="button"
              className="filter"
              aria-pressed={chosen === option.value}
              onClick={() => {
                setChosen(option.value)
              }}
            >
              {option.label}
            </button>
          ))}
        </div>
      </div>

      {rows.length === 0 && !showContact ? (
        <div className="empty-state">
          <h2>{here ? emptyMessage(chosen) : 'Reading the inbox…'}</h2>
          <p>Work that needs a decision or a review will appear here.</p>
        </div>
      ) : (
        <ul className="attention-list" data-testid="attention-list">
          {showContact ? (
            <li key="contact">
              <Card
                data-kind="disconnected"
                data-testid="attention-contact"
                data-level={urgent ? 'urgent' : 'notable'}
                data-host={lost.name}
              >
                <div className="attention-top">
                  <span className="row">
                    <Badge tone={BADGE_TONE.muted}>{KIND_LABEL.disconnected}</Badge>
                    <span className="small faint">{lost.name}</span>
                  </span>
                  {urgent ? <Badge tone="danger">Urgent</Badge> : null}
                </div>
                <div className="attention-body">
                  <h2>{lost.name} is out of contact</h2>
                  <p>
                    {contactWords(lost.sinceMs, nowMs)}
                    {here === null
                      ? ''
                      : ` What is listed here from it was read ${describeElapsed(nowMs - here.atMs)} ago.`}
                  </p>
                </div>
                <div className="card-footer">
                  <span className="small faint">Nothing here is a failure.</span>
                </div>
              </Card>
            </li>
          ) : null}
          {rows.map((row) => {
            const sessionId = row.item.session_id
            const number = sessionId === null ? undefined : numbered.get(sessionId)
            // A session's approvals, and its questions, are listed once however many rows the host
            // raised for them: each row is for one request, and a panel lists the session's all.
            const approvals =
              row.item.rule === 'attention.pending_approval' &&
              sessionId !== null &&
              !approvalsShown.has(sessionId)
            if (approvals) approvalsShown.add(sessionId)
            const questions =
              asksAQuestion(row) && sessionId !== null && !questionsShown.has(sessionId)
            if (questions) questionsShown.add(sessionId)
            return (
              <li key={row.item.key}>
                <Card
                  data-kind={row.kind}
                  data-testid={`attention-${row.kind}`}
                  data-level={row.item.level}
                >
                  <div className="attention-top">
                    <span className="row">
                      <Badge tone={BADGE_TONE[row.tone]}>{row.label}</Badge>
                      <span className="small faint">
                        {sessionId === null
                          ? 'This host'
                          : number === undefined
                            ? 'A session'
                            : `Session ${number}`}
                      </span>
                    </span>
                    {row.item.level === 'urgent' ? <Badge tone="danger">Urgent</Badge> : null}
                  </div>
                  <div className="attention-body">
                    <h2>{row.title}</h2>
                    <p data-testid={row.kind === 'disconnected' ? 'disconnected-note' : undefined}>
                      {row.detail}
                    </p>
                    {approvals ? (
                      <ApprovalRequests
                        sessionId={sessionId}
                        onAnswered={readAgain}
                        openTerminal={() => {
                          go({ view: 'session', sessionId, pane: 'terminal' })
                        }}
                      />
                    ) : null}
                    {questions && sessionId !== null ? (
                      <QuestionRequests sessionId={sessionId} onAnswered={readAgain} />
                    ) : null}
                  </div>
                  <div className="card-footer">
                    <span className="small faint">
                      {row.kind === 'disconnected'
                        ? 'Nothing here is a failure.'
                        : row.kind === 'notice'
                          ? 'Nothing here needs a decision.'
                          : ''}
                    </span>
                    <span className="row">
                      {sessionId !== null ? (
                        <Button
                          onClick={() => {
                            go({ view: 'session', sessionId, pane: 'semantic' })
                          }}
                        >
                          Open session
                        </Button>
                      ) : null}
                      {row.kind === 'awaiting_review' ? (
                        <Button
                          onClick={() => {
                            go({ view: 'changesets' })
                          }}
                        >
                          Review changes
                        </Button>
                      ) : null}
                      <Button
                        tone="quiet"
                        data-testid="acknowledge"
                        onClick={() => {
                          acknowledge(row)
                        }}
                      >
                        Mark as seen
                      </Button>
                    </span>
                  </div>
                </Card>
              </li>
            )
          })}
        </ul>
      )}
    </>
  )
}
