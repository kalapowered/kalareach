/**
 * The attention inbox: what the phone opens on.
 *
 * Every host, every session, one list. The kinds are told apart three ways at once, because one way
 * is never enough: a word, a tone, and the sentence underneath. A host that cannot be reached is
 * drawn as exactly that, is never counted among the failures, and says in so many words that its
 * sessions may still be running.
 *
 * The host in use is read with the page's own reads; every other host this phone is paired with is
 * visited by native code (`useOtherHosts`), and its rows are named by the host they are from. What
 * a host was last read to hold stays while contact with it is out, said to be from that read. A row
 * of another host is answered or opened by taking that host into use first.
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
  addCounts,
  ATTENTION_READ_CADENCE_MS,
  contactWords,
  count,
  describeElapsed,
  emptyMessage,
  inboxNotes,
  KIND_LABEL,
  order,
  orderAcrossHosts,
  readWholeInbox,
  type AttentionCounts,
  type AttentionFilter,
  type HostedRow,
  type HostTag
} from '../../model/attention'
import { Confirmations } from '../../pairing/Confirmations'
import { ApprovalRequests } from '../../views/Approvals'
import { KeptAnswers, QuestionRequests } from '../../views/Questions'
import { ask } from '../model/call'
import { useOtherHosts } from '../model/hosts-inbox'
import { useKeepPlace } from '../model/keep-place'
import { minimumTarget, type Surface } from '../platform'
import { Offers } from './Offers'

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

/** What the shell knows of the connection to the host in use. */
export interface InboxConnection {
  /** Whether the host in use answers, or null before anything has said. */
  readonly connected: boolean | null
  /** When this window heard that contact was lost, while it is. */
  readonly lostSinceMs: number | null
}

/** A host that does not answer, as the inbox draws it. */
interface Contact {
  readonly host: HostTag
  /** Since when contact has been lost, when this device noted it. */
  readonly sinceMs: number | null
  /** When the rows listed for this host were read, while any are. */
  readonly rowsReadAtMs: number | null
}

/** No counts. */
const NOTHING: AttentionCounts = {
  pending_decision: 0,
  failed_action: 0,
  awaiting_review: 0,
  disconnected: 0,
  notice: 0,
  actionable: 0
}

/** The inbox screen. */
export function Inbox({
  surface,
  connection = null,
  onOpenSession,
  onCounts
}: {
  readonly surface: Surface
  /** What the shell knows of the host in use; null before it has said anything. */
  readonly connection?: InboxConnection | null
  readonly onOpenSession: (sessionId: string) => void
  readonly onCounts?: (actionable: number) => void
}): ReactNode {
  const { port, say } = useApp()
  // What the host in use said, with the host it said it for: a read that answers after the phone
  // went to another host is that host's no longer, and is not shown as the new one's.
  const [inbox, setInbox] = useState<{
    readonly reference: string | null
    readonly result: AttentionReadResult
    readonly atMs: number
  } | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [chosen, setChosen] = useState<AttentionFilter>('all')
  const [open, setOpen] = useState<HostedRow | null>(null)
  // Each session's display number, by its identifier, as the host in use listed them.
  const [numbers, setNumbers] = useState<ReadonlyMap<string, string>>(new Map())
  const [nowMs, setNowMs] = useState(() => Date.now())
  const others = useOtherHosts()
  const { again: seeOthersAgain } = others
  const target = minimumTarget(surface)
  // What the person is reading stays where it is when something arrives above it.
  const content = useRef<HTMLDivElement | null>(null)
  useKeepPlace(content)

  // Every read of the inbox, on opening, on the cadence, when the connection changes and after an
  // answer, goes through one cadence under one watch: one read at a time, only the newest read's
  // answer shown, and none once the screen closes.
  const reads = useRef<Watch | null>(null)
  const again = useRef<() => void>(() => undefined)

  const load = useCallback((): Promise<void> => {
    const current = reads.current?.read() ?? null
    if (current === null) return Promise.resolve()
    // The host in use as this read begins and as it ends: one that changed in between is not the
    // host the answer is of.
    const using = () =>
      port
        .pairingView()
        .then((view) => view.hosts.find((each) => each.in_use)?.reference ?? null)
        .catch(() => null)
    const began = using()
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
      .then(async (answer) => {
        const [before, after] = [await began, await using()]
        if (!current() || before !== after) return
        setInbox({ reference: after, result: answer, atMs: Date.now() })
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
    return Promise.all([inboxRead, numbersRead]).then(() => {
      if (current()) setNowMs(Date.now())
    })
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

  // The host in use's rows are those read for the host in use now.
  const here =
    inbox !== null && inbox.reference === (others.paired?.inUseReference ?? null) ? inbox : null
  const inUseName = others.paired?.inUseName ?? null
  const several = (others.paired?.count ?? 1) > 1
  const inUse: HostTag = useMemo(
    () => ({ reference: null, name: inUseName ?? 'This host' }),
    [inUseName]
  )

  // Every host's rows, with the numbers its sessions go by and the host they are from.
  const hosted = useMemo<readonly HostedRow[]>(() => {
    const rows: HostedRow[] = []
    if (here !== null) {
      for (const row of order(here.result, here.atMs)) rows.push({ row, host: inUse, numbers })
    }
    for (const visit of others.hosts ?? []) {
      const read = visit.state === 'read' ? visit : others.lastRead.get(visit.reference)
      if (read === undefined || read.result === null) continue
      const named = new Map(read.sessions.map((each) => [each.session_id, each.display_number]))
      const host: HostTag = { reference: visit.reference, name: visit.name }
      for (const row of order(read.result, read.read_at_ms ?? nowMs)) {
        rows.push({ row, host, numbers: named })
      }
    }
    return orderAcrossHosts(rows)
  }, [here, inUse, numbers, others.hosts, others.lastRead, nowMs])

  // The hosts that do not answer: the host in use, by what the shell heard, and the others, by
  // what their visits found.
  const contacts = useMemo<readonly Contact[]>(() => {
    const lost: Contact[] = []
    if (connection?.connected === false && inUseName !== null) {
      lost.push({
        host: inUse,
        sinceMs: connection.lostSinceMs,
        rowsReadAtMs: here?.atMs ?? null
      })
    }
    for (const visit of others.hosts ?? []) {
      if (visit.state !== 'out_of_contact') continue
      lost.push({
        host: { reference: visit.reference, name: visit.name },
        sinceMs: visit.lost_since_ms,
        rowsReadAtMs: others.lastRead.get(visit.reference)?.read_at_ms ?? null
      })
    }
    return lost
  }, [connection, inUseName, inUse, here, others.hosts, others.lastRead])

  const counts = useMemo(() => {
    let total = here === null ? NOTHING : count(here.result)
    for (const visit of others.hosts ?? []) {
      const read = visit.state === 'read' ? visit : others.lastRead.get(visit.reference)
      if (read !== undefined && read.result !== null) total = addCounts(total, count(read.result))
    }
    return { ...total, disconnected: total.disconnected + contacts.length }
  }, [here, others.hosts, others.lastRead, contacts])

  useEffect(() => {
    if (onCounts) onCounts(counts.actionable)
  }, [counts, onCounts])

  const notes = useMemo(() => (here ? inboxNotes(here.result) : []), [here])
  const shown = chosen === 'all' ? hosted : hosted.filter((each) => each.row.kind === chosen)
  const showContacts = chosen === 'all' || chosen === 'disconnected'
  const whereOf = (entry: HostedRow): string => {
    const sessionId = entry.row.item.session_id
    const named = several ? `${entry.host.name} · ` : ''
    if (sessionId === null) return several ? entry.host.name : 'This host'
    const number = entry.numbers.get(sessionId)
    return `${named}${number === undefined ? 'A session' : `Session ${number}`}`
  }
  // A row of another host is answered where that host's worker is, so the host is taken into use
  // first. A host that cannot be taken says why, and nothing opens.
  const choose = useCallback(
    (entry: HostedRow) => {
      void (async () => {
        if (entry.host.reference !== null) {
          try {
            await port.hostsUse(entry.host.reference)
          } catch (failure: unknown) {
            say(failureMessage(failure), 'danger')
            return
          }
          seeOthersAgain()
        }
        if (entry.row.actionable) setOpen(entry)
        else if (entry.row.item.session_id) onOpenSession(entry.row.item.session_id)
      })()
    },
    [port, say, seeOthersAgain, onOpenSession]
  )
  // The generic words for a host that could not be read give way to the row that says it better.
  const inUseOut = contacts.some((each) => each.host.reference === null)

  return (
    <div ref={content}>
      <Confirmations surface={surface} />
      <Offers surface={surface} />

      {error && !inUseOut ? (
        <Banner
          tone="warning"
          title="The inbox could not be read"
          detail={`${sentence(error)} Anything running on your hosts is unaffected.`}
        />
      ) : null}

      <KeptAnswers />

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
            {each.id !== 'all' && counts[each.id] > 0 ? ` (${counts[each.id]})` : ''}
          </button>
        ))}
      </div>

      {notes.length > 0 ? (
        <ul className="m-notes" data-testid="inbox-notes">
          {notes.map((note) => (
            <li key={note}>{note}</li>
          ))}
        </ul>
      ) : null}

      {showContacts && contacts.length > 0 ? (
        <ul className="m-list" data-testid="inbox-contacts">
          {contacts.map((each) => (
            <li key={each.host.reference ?? 'in-use'}>
              <div
                className="m-row"
                data-tone="muted"
                data-kind="disconnected"
                data-host={each.host.name}
                data-testid="inbox-contact"
                style={{ minBlockSize: target }}
              >
                <span className="m-row-head">
                  <span className="m-row-kind">{KIND_LABEL.disconnected}</span>
                  <span className="m-row-where">{each.host.name}</span>
                </span>
                <span className="m-row-title">{each.host.name} is out of contact</span>
                <span className="m-row-detail">
                  {contactWords(each.sinceMs, nowMs)}
                  {each.rowsReadAtMs === null
                    ? ''
                    : ` What is listed here from it was read ${describeElapsed(nowMs - each.rowsReadAtMs)} ago.`}
                </span>
              </div>
            </li>
          ))}
        </ul>
      ) : null}

      {shown.length === 0 && !(showContacts && contacts.length > 0) ? (
        <p className="m-empty">
          {here !== null ? emptyMessage(chosen) : 'Reading the inbox…'}
        </p>
      ) : (
        <ul className="m-list">
          {shown.map((entry) => (
            <li key={`${entry.host.reference ?? 'in-use'}:${entry.row.item.key}`}>
              <button
                type="button"
                className="m-row"
                data-tone={entry.row.tone}
                data-kind={entry.row.kind}
                data-attention={entry.row.item.key}
                data-host={entry.host.name}
                style={{ minBlockSize: target }}
                aria-label={`${entry.row.announcement} ${whereOf(entry)}.`}
                onClick={() => {
                  choose(entry)
                }}
              >
                <span className="m-row-head">
                  <span className="m-row-kind">{entry.row.label}</span>
                  <span className="m-row-where">{whereOf(entry)}</span>
                </span>
                <span className="m-row-title">{entry.row.title}</span>
                <span className="m-row-detail">{entry.row.detail}</span>
              </button>
            </li>
          ))}
        </ul>
      )}

      <Sheet
        open={open !== null}
        title={open?.row.title ?? ''}
        description={open ? whereOf(open) : undefined}
        closeLabel="Close item"
        // The decisions are at the foot of the body, above a footer that only opens the session: a
        // message in a row under the body would take its foot from view, so it is drawn above it.
        messageAt="head"
        onClose={() => {
          setOpen(null)
        }}
        footer={
          open?.row.item.session_id ? (
            <Button
              onClick={() => {
                const sessionId = open.row.item.session_id
                setOpen(null)
                if (sessionId) onOpenSession(sessionId)
              }}
            >
              Open the session
            </Button>
          ) : null
        }
      >
        {open?.row.item.session_id ? (
          <ApprovalRequests
            sessionId={open.row.item.session_id}
            onAnswered={() => {
              again.current()
            }}
          />
        ) : null}
        {open?.row.item.session_id &&
        (open.row.item.rule === 'attention.pending_input' ||
          open.row.item.rule === 'attention.input_idle_reminder') ? (
          <QuestionRequests
            sessionId={open.row.item.session_id}
            onAnswered={() => {
              again.current()
            }}
          />
        ) : null}
      </Sheet>
    </div>
  )
}

