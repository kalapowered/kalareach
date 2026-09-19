/**
 * The attention inbox: what the phone opens on.
 *
 * Every host, every session, one list. The four kinds are told apart three ways at once, because
 * one way is never enough: a word, a tone, and the sentence underneath. A host that cannot be
 * reached is drawn as exactly that, is never counted among the failures, and says in so many words
 * that its sessions may still be running.
 *
 * A decision is answered here rather than three screens away, because answering it is why the
 * person picked up the phone. The control is the one that commits on a completed action, so a
 * pocket press decides nothing.
 */

import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react'

import { Banner, Button, CommitButton, Sheet } from '../../components/ui'
import { useApp } from '../../app/state'
import { failureMessage } from '../../host/port'
import type { AttentionEntry, AttentionInbox } from '../../model/pending'
import { ask } from '../model/call'
import { count, emptyMessage, filter, locationOf, order, type InboxFilter } from '../model/inbox'
import { minimumTarget, type Surface } from '../platform'

/** A host's own words, ended so the sentence after them reads as a second sentence. */
function sentence(text: string): string {
  const trimmed = text.trim()
  if (trimmed.length === 0) return ''
  return /[.!?]$/.test(trimmed) ? trimmed : `${trimmed}.`
}

const FILTERS: readonly { readonly id: InboxFilter; readonly label: string }[] = [
  { id: 'all', label: 'Everything' },
  { id: 'pending_decision', label: 'Waiting for you' },
  { id: 'failed_action', label: 'Failed' },
  { id: 'awaiting_review', label: 'To review' },
  { id: 'disconnected', label: 'Out of contact' }
]

/** The inbox screen. */
export function Inbox({
  surface,
  onOpenSession,
  onCounts
}: {
  readonly surface: Surface
  readonly onOpenSession: (sessionId: string) => void
  readonly onCounts?: (actionable: number) => void
}): ReactNode {
  const { port, say } = useApp()
  const [inbox, setInbox] = useState<AttentionInbox | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [chosen, setChosen] = useState<InboxFilter>('all')
  const [open, setOpen] = useState<AttentionEntry | null>(null)
  const target = minimumTarget(surface)

  const read = useCallback(() => {
    ask(() => port.attentionRead({}))
      .then((answer) => {
        setInbox(answer)
        setError(null)
      })
      .catch((failure: unknown) => {
        // A host that cannot be read is a host out of contact, which is a state the inbox has. It
        // is never a claim that anything on it failed.
        setError(failureMessage(failure))
      })
  }, [port])

  useEffect(() => {
    read()
    const stop = port.subscribe((event) => {
      const body = event.body as { kind?: string }
      if (body.kind === 'attention' || body.kind === 'connection') read()
    })
    return stop
  }, [port, read])

  const rows = useMemo(() => (inbox ? order(inbox) : []), [inbox])
  const counts = useMemo(() => (inbox ? count(inbox) : null), [inbox])

  useEffect(() => {
    if (counts && onCounts) onCounts(counts.actionable)
  }, [counts, onCounts])

  const shown = filter(rows, chosen)

  const respond = (entry: AttentionEntry, allowed: boolean) => {
    ask(() =>
      port.approvalRespond(
        { approval_request_id: entry.approval_request_id, decision: allowed ? 'allow' : 'deny' },
        { sessionId: entry.session_id ?? undefined, sessionEpoch: entry.session_epoch ?? undefined }
      )
    )
      .then((settled) => {
        // The receipt is the outcome. A request that was accepted is not a request that was applied.
        const state = settled.receipt?.state ?? 'unknown'
        say(
          state === 'applied'
            ? allowed
              ? 'Allowed.'
              : 'Denied.'
            : `Sent. The host has not confirmed it yet (${state}).`,
          state === 'applied' ? 'success' : 'pending'
        )
        setOpen(null)
        read()
      })
      .catch((failure: unknown) => {
        say(failureMessage(failure), 'danger')
      })
  }

  return (
    <>
      {error ? (
        <Banner
          tone="warning"
          title="The inbox could not be read"
          detail={`${sentence(error)} Anything running on your hosts is unaffected.`}
        />
      ) : null}

      <div className="m-filters" role="group" aria-label="Filter the inbox">
        {FILTERS.map((each) => (
          <button
            key={each.id}
            type="button"
            className="m-filter"
            style={{ minBlockSize: target }}
            aria-pressed={chosen === each.id}
            onClick={() => {
              setChosen(each.id)
            }}
          >
            {each.label}
            {counts && each.id !== 'all' && counts[each.id] > 0 ? ` (${counts[each.id]})` : ''}
          </button>
        ))}
      </div>

      {shown.length === 0 ? (
        <p className="m-empty">{inbox ? emptyMessage(chosen) : 'Reading the inbox…'}</p>
      ) : (
        <ul className="m-list">
          {shown.map((row) => (
            <li key={row.entry.attention_id}>
              <button
                type="button"
                className="m-row"
                data-tone={row.tone}
                data-kind={row.entry.kind}
                data-attention={row.entry.attention_id}
                style={{ minBlockSize: target }}
                aria-label={row.announcement}
                onClick={() => {
                  if (row.actionable) setOpen(row.entry)
                  else if (row.entry.session_id) onOpenSession(row.entry.session_id)
                }}
              >
                <span className="m-row-head">
                  <span className="m-row-kind">{row.label}</span>
                  <span className="m-row-where">{locationOf(row.entry)}</span>
                </span>
                <span className="m-row-title">{row.entry.title}</span>
                <span className="m-row-detail">{row.detail}</span>
              </button>
            </li>
          ))}
        </ul>
      )}

      <Sheet
        open={open !== null}
        title={open?.title ?? ''}
        description={open ? locationOf(open) : undefined}
        onClose={() => {
          setOpen(null)
        }}
        footer={
          open ? (
            <>
              <Button
                onClick={() => {
                  respond(open, false)
                }}
              >
                Deny
              </Button>
              <CommitButton
                tone="primary"
                onCommit={() => {
                  respond(open, true)
                }}
              >
                Allow
              </CommitButton>
            </>
          ) : null
        }
      >
        {open ? (
          <>
            <p>{open.detail}</p>
            {open.command_preview ? (
              <pre className="code-block">
                <code>{open.command_preview}</code>
              </pre>
            ) : null}
            <p className="m-hint">
              Allowing runs it on {open.host_label}. Nothing runs until the host confirms it.
            </p>
          </>
        ) : null}
      </Sheet>
    </>
  )
}
