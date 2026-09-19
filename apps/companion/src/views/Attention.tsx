/**
 * The attention inbox.
 *
 * Four states, kept apart on purpose. A pending decision is something waiting for the person. A
 * failed action is something that finished badly and says why. Completed work awaiting review is
 * finished and fine. A disconnected host is none of those: it is the absence of contact, and the
 * one thing this screen must never do is turn silence into a claim that an agent is stuck.
 */

import { useCallback, useEffect, useState, type ReactNode } from 'react'

import { Badge, Banner, Button, Card, CommitButton } from '../components/ui'
import { ENVIRONMENT_ID, useApp } from '../app/state'
import { failureMessage } from '../host/port'
import type { AttentionEntry, AttentionInbox, AttentionKind } from '../model/pending'

const FILTERS: readonly { readonly value: AttentionKind | 'all'; readonly label: string }[] = [
  { value: 'all', label: 'Everything' },
  { value: 'pending_decision', label: 'Decisions' },
  { value: 'failed_action', label: 'Failures' },
  { value: 'awaiting_review', label: 'To review' },
  { value: 'disconnected', label: 'Out of contact' }
]

/** What each kind is called and how it is coloured. */
export function describeKind(kind: AttentionKind): {
  readonly label: string
  readonly tone: 'warning' | 'danger' | 'success' | 'neutral'
} {
  switch (kind) {
    case 'pending_decision':
      return { label: 'Waiting for you', tone: 'warning' }
    case 'failed_action':
      return { label: 'Did not finish', tone: 'danger' }
    case 'awaiting_review':
      return { label: 'Ready to review', tone: 'success' }
    case 'disconnected':
      return { label: 'Out of contact', tone: 'neutral' }
  }
}

/** How long ago, in the words a person uses. */
export function ago(ms: number): string {
  const minutes = Math.round(ms / 60_000)
  if (minutes < 1) return 'just now'
  if (minutes < 60) return `${minutes} min ago`
  const hours = Math.round(minutes / 60)
  if (hours < 24) return `${hours} h ago`
  return `${Math.round(hours / 24)} d ago`
}

/** The inbox. */
export function Attention(): ReactNode {
  const { port, go, say } = useApp()
  const [inbox, setInbox] = useState<AttentionInbox | null>(null)
  const [failure, setFailure] = useState<string | null>(null)
  const [filter, setFilter] = useState<AttentionKind | 'all'>('all')
  const [readAtMs, setReadAtMs] = useState(0)

  const load = useCallback(() => {
    port
      .attentionRead(ENVIRONMENT_ID, {})
      .then((result) => {
        setInbox(result)
        setReadAtMs(Date.now())
        setFailure(null)
      })
      .catch((error: unknown) => {
        setFailure(failureMessage(error))
      })
  }, [port])

  useEffect(load, [load])

  const decide = (entry: AttentionEntry, decision: 'allow' | 'deny') => {
    port
      .approvalRespond(ENVIRONMENT_ID, {
        approval_request_id: entry.approval_request_id,
        decision
      })
      .then((settled) => {
        // The completion feedback waits for the receipt: the host said what happened, not the
        // network.
        say(
          settled.receipt?.state === 'applied'
            ? decision === 'allow'
              ? 'Allowed.'
              : 'Denied.'
            : 'Sent. Waiting for the host to confirm.'
        )
        load()
      })
      .catch((error: unknown) => {
        say(failureMessage(error), 'danger')
      })
  }

  const entries = (inbox?.entries ?? []).filter(
    (entry) => filter === 'all' || entry.kind === filter
  )

  return (
    <>
      <header className="page-heading">
        <div>
          <p className="eyebrow">Attention</p>
          <h1>What needs you</h1>
          <p>Decisions, failures and finished work, across every host you have paired.</p>
        </div>
      </header>

      {failure ? (
        <Banner
          tone="warning"
          title="This list could not be read"
          detail={failure}
          action={<Button onClick={load}>Try again</Button>}
        />
      ) : null}

      <div className="toolbar">
        <div className="filters" role="group" aria-label="Filter the inbox">
          {FILTERS.map((option) => (
            <button
              key={option.value}
              type="button"
              className="filter"
              aria-pressed={filter === option.value}
              onClick={() => {
                setFilter(option.value)
              }}
            >
              {option.label}
            </button>
          ))}
        </div>
      </div>

      {entries.length === 0 ? (
        <div className="empty-state">
          <h2>Nothing is waiting</h2>
          <p>Work that needs a decision or a review will appear here.</p>
        </div>
      ) : (
        <ul className="attention-list" data-testid="attention-list">
          {entries.map((entry) => (
            <li key={entry.attention_id}>
              <Card data-kind={entry.kind} data-testid={`attention-${entry.kind}`}>
                <div className="attention-top">
                  <span className="row">
                    <Badge tone={describeKind(entry.kind).tone}>{describeKind(entry.kind).label}</Badge>
                    <span className="small faint">
                      {entry.host_label}
                      {entry.session_display_number ? ` · session ${entry.session_display_number}` : ''}
                      {entry.application ? ` · ${entry.application}` : ''}
                    </span>
                  </span>
                  <span className="small faint">{ago(readAtMs - entry.raised_at_ms)}</span>
                </div>
                <div className="attention-body">
                  <h2>{entry.title}</h2>
                  <p>{entry.detail}</p>
                  {entry.command_preview ? (
                    <p className="command-preview">
                      <code>{entry.command_preview}</code>
                    </p>
                  ) : null}
                  {entry.error_code ? (
                    <p className="small faint">Host reported {entry.error_code}.</p>
                  ) : null}
                  {entry.kind === 'disconnected' ? (
                    <p className="small faint" data-testid="disconnected-note">
                      Out of contact for {ago(entry.out_of_contact_ms ?? 0)}. Elapsed time does not
                      say what its processes are doing.
                    </p>
                  ) : null}
                </div>
                <div className="card-footer">
                  <span className="small faint">
                    {entry.kind === 'pending_decision'
                      ? 'This runs on your host if you allow it.'
                      : entry.kind === 'disconnected'
                        ? 'Nothing here is a failure.'
                        : ''}
                  </span>
                  <span className="row">
                    {entry.kind === 'pending_decision' ? (
                      <>
                        <CommitButton
                          tone="danger"
                          onCommit={() => {
                            decide(entry, 'deny')
                          }}
                        >
                          Deny
                        </CommitButton>
                        <CommitButton
                          tone="sage"
                          onCommit={() => {
                            decide(entry, 'allow')
                          }}
                        >
                          Allow
                        </CommitButton>
                      </>
                    ) : null}
                    {entry.session_id ? (
                      <Button
                        onClick={() => {
                          go({ view: 'session', sessionId: entry.session_id!, pane: 'semantic' })
                        }}
                      >
                        Open session
                      </Button>
                    ) : null}
                    {entry.kind === 'awaiting_review' ? (
                      <Button
                        onClick={() => {
                          go({ view: 'changesets' })
                        }}
                      >
                        Review changes
                      </Button>
                    ) : null}
                  </span>
                </div>
              </Card>
            </li>
          ))}
        </ul>
      )}
    </>
  )
}
