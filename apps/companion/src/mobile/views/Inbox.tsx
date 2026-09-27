/**
 * The attention inbox: what the phone opens on.
 *
 * Every host, every session, one list. The kinds are told apart three ways at once, because one way
 * is never enough: a word, a tone, and the sentence underneath. A host that cannot be reached is
 * drawn as exactly that, is never counted among the failures, and says in so many words that its
 * sessions may still be running.
 *
 * An approval is answered here rather than three screens away, because answering it is why the
 * person picked up the phone. The sheet lists what the session's agent is waiting for, with the
 * decisions its decoder offered, and each control commits on a completed action, so a pocket press
 * decides nothing.
 */

import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react'

import type { AttentionReadResult } from '@kalareach/protocol'

import { Banner, Button, Sheet } from '../../components/ui'
import { readOnCadence } from '../../app/cadence'
import { useApp } from '../../app/state'
import { failureMessage, watch, type Watch } from '../../host/port'
import {
  ATTENTION_READ_CADENCE_MS,
  count,
  emptyMessage,
  filter,
  order,
  type AttentionFilter,
  type AttentionRow
} from '../../model/attention'
import { ApprovalRequests } from '../../views/Approvals'
import { ask } from '../model/call'
import { minimumTarget, type Surface } from '../platform'

/** A host's own words, ended so the sentence after them reads as a second sentence. */
function sentence(text: string): string {
  const trimmed = text.trim()
  if (trimmed.length === 0) return ''
  return /[.!?]$/.test(trimmed) ? trimmed : `${trimmed}.`
}

const FILTERS: readonly { readonly id: AttentionFilter; readonly label: string }[] = [
  { id: 'all', label: 'Everything' },
  { id: 'pending_decision', label: 'Waiting for you' },
  { id: 'failed_action', label: 'Failed' },
  { id: 'awaiting_review', label: 'To review' },
  { id: 'disconnected', label: 'Out of contact' },
  { id: 'notice', label: 'Notices' }
]

/** The largest page of the inbox one read asks for. */
const PAGE_ITEMS = '200'

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
  const { port } = useApp()
  const [inbox, setInbox] = useState<{ readonly result: AttentionReadResult; readonly atMs: number } | null>(
    null
  )
  const [error, setError] = useState<string | null>(null)
  const [chosen, setChosen] = useState<AttentionFilter>('all')
  const [open, setOpen] = useState<AttentionRow | null>(null)
  // Each session's display number, by its identifier, as the host listed them.
  const [numbers, setNumbers] = useState<ReadonlyMap<string, string>>(new Map())
  const target = minimumTarget(surface)

  // Every read of the inbox, on opening, on the cadence, when the connection changes and after an
  // answer, goes through one cadence under one watch: one read at a time, only the newest read's
  // answer shown, and none once the screen closes.
  const reads = useRef<Watch | null>(null)
  const again = useRef<() => void>(() => undefined)

  const load = useCallback((): Promise<void> => {
    const current = reads.current?.read() ?? null
    if (current === null) return Promise.resolve()
    const inboxRead = ask(() =>
      port.attentionRead({
        session_id: null,
        include_acknowledged: false,
        max_items: PAGE_ITEMS,
        after: null
      })
    )
      .then((answer) => {
        if (!current()) return
        setInbox({ result: answer, atMs: Date.now() })
        setError(null)
      })
      .catch((failure: unknown) => {
        if (!current()) return
        // A host that cannot be read is a host out of contact, which is a state the inbox has.
        // It is never a claim that anything on it failed.
        setError(failureMessage(failure))
      })
    const numbersRead = ask(() => port.sessionList({ environment_id: null, include_closed: false }))
      .then((list) => {
        if (!current()) return
        setNumbers(new Map(list.sessions.map((session) => [session.session_id, session.display_number])))
      })
      .catch(() => undefined)
    return Promise.all([inboxRead, numbersRead]).then(() => undefined)
  }, [port])

  // The inbox is read once the connection listener is registered, so no change of connection falls
  // between the read and it, and read again on the cadence and on each change of connection.
  useEffect(() => {
    const cadence = readOnCadence(load, ATTENTION_READ_CADENCE_MS)
    const reading = watch([port.onConnection(cadence.now)], cadence.now, (failure) => {
      setError(failureMessage(failure))
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

  const rows = useMemo(() => (inbox ? order(inbox.result, inbox.atMs) : []), [inbox])
  const counts = useMemo(() => (inbox ? count(inbox.result) : null), [inbox])

  useEffect(() => {
    if (counts && onCounts) onCounts(counts.actionable)
  }, [counts, onCounts])

  const shown = filter(rows, chosen)
  const whereOf = (row: AttentionRow): string => {
    const sessionId = row.item.session_id
    if (sessionId === null) return 'This host'
    const number = numbers.get(sessionId)
    return number === undefined ? 'A session' : `Session ${number}`
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
            <li key={row.item.key}>
              <button
                type="button"
                className="m-row"
                data-tone={row.tone}
                data-kind={row.kind}
                data-attention={row.item.key}
                style={{ minBlockSize: target }}
                aria-label={`${row.announcement} ${whereOf(row)}.`}
                onClick={() => {
                  if (row.actionable) setOpen(row)
                  else if (row.item.session_id) onOpenSession(row.item.session_id)
                }}
              >
                <span className="m-row-head">
                  <span className="m-row-kind">{row.label}</span>
                  <span className="m-row-where">{whereOf(row)}</span>
                </span>
                <span className="m-row-title">{row.title}</span>
                <span className="m-row-detail">{row.detail}</span>
              </button>
            </li>
          ))}
        </ul>
      )}

      <Sheet
        open={open !== null}
        title={open?.title ?? ''}
        description={open ? whereOf(open) : undefined}
        onClose={() => {
          setOpen(null)
        }}
        footer={
          open?.item.session_id ? (
            <Button
              onClick={() => {
                const sessionId = open.item.session_id
                setOpen(null)
                if (sessionId) onOpenSession(sessionId)
              }}
            >
              Open the session
            </Button>
          ) : null
        }
      >
        {open?.item.session_id ? (
          <ApprovalRequests
            sessionId={open.item.session_id}
            onAnswered={() => {
              again.current()
            }}
          />
        ) : null}
      </Sheet>
    </>
  )
}
