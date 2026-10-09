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

import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react'

import type { AttentionReadResult } from '@kalareach/protocol'

import { Badge, Banner, Button, Card } from '../components/ui'
import { readOnCadence } from '../app/cadence'
import { useApp } from '../app/state'
import { failureMessage, watch, type Watch } from '../host/port'
import { ask } from '../mobile/model/call'
import {
  ATTENTION_READ_CADENCE_MS,
  emptyMessage,
  filter as filtered,
  inboxNotes,
  order,
  readWholeInbox,
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

/** The inbox. */
export function Attention(): ReactNode {
  const { port, go, say } = useApp()
  const [inbox, setInbox] = useState<AttentionReadResult | null>(null)
  const [readAtMs, setReadAtMs] = useState(0)
  const [failure, setFailure] = useState<string | null>(null)
  const [chosen, setChosen] = useState<AttentionFilter>('all')
  // Each session's display number, by its identifier, as the host listed them.
  const [numbers, setNumbers] = useState<ReadonlyMap<string, string>>(new Map())
  // Every read of the inbox, on opening, on the cadence, after an answer and on a retry, goes
  // through one cadence under one watch with no listeners: one read at a time, only the newest
  // read's answer shown, and none once the screen closes.
  const reads = useRef<Watch | null>(null)
  const again = useRef<() => void>(() => undefined)

  const load = useCallback((): Promise<void> => {
    const current = reads.current?.read() ?? null
    if (current === null) return Promise.resolve()
    const inboxRead = ask(() =>
      readWholeInbox((after) =>
        port.attentionRead({
          session_id: null,
          include_acknowledged: false,
          max_items: PAGE_ITEMS,
          after
        })
      )
    )
      .then((result) => {
        if (!current()) return
        setInbox(result)
        setReadAtMs(Date.now())
        setFailure(null)
      })
      .catch((error: unknown) => {
        if (!current()) return
        setFailure(failureMessage(error))
      })
    // Only for the words: an inbox read without them names a session by nothing but the item.
    const numbersRead = ask(() => port.sessionList({ environment_id: null, include_closed: false }))
      .then((list) => {
        if (!current()) return
        setNumbers(new Map(list.sessions.map((session) => [session.session_id, session.display_number])))
      })
      .catch(() => undefined)
    return Promise.all([inboxRead, numbersRead]).then(() => undefined)
  }, [port])

  useEffect(() => {
    const cadence = readOnCadence(load, ATTENTION_READ_CADENCE_MS)
    const reading = watch([], cadence.now)
    reads.current = reading
    again.current = cadence.now
    return () => {
      cadence.stop()
      reading.stop()
      if (reads.current === reading) reads.current = null
      again.current = () => undefined
    }
  }, [load])

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

  const rows = inbox ? filtered(order(inbox, readAtMs), chosen) : []
  const notes = inbox ? inboxNotes(inbox) : []
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

      {failure ? (
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

      {rows.length === 0 ? (
        <div className="empty-state">
          <h2>{inbox ? emptyMessage(chosen) : 'Reading the inbox…'}</h2>
          <p>Work that needs a decision or a review will appear here.</p>
        </div>
      ) : (
        <ul className="attention-list" data-testid="attention-list">
          {rows.map((row) => {
            const sessionId = row.item.session_id
            const number = sessionId === null ? undefined : numbers.get(sessionId)
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
                      <ApprovalRequests sessionId={sessionId} onAnswered={readAgain} />
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
