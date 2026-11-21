/**
 * The attention inbox: what the phone opens on.
 *
 * Every host, every session, one list. The kinds are told apart three ways at once, because one way
 * is never enough: a word, a tone, and the sentence underneath. A host that cannot be reached is
 * drawn as exactly that, is never counted among the failures, and says in so many words that its
 * sessions may still be running. A host that answers and refuses is another thing: it is in contact,
 * it said no, and its row says which request of the visit it refused (who it is, the session, the
 * connection or the inbox) and gives the host's words and what the person can do about them.
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

import { Badge, Banner, Button, Sheet } from '../../components/ui'
import { readOnCadence } from '../../app/cadence'
import { useApp } from '../../app/state'
import {
  failureCode,
  failureMessage,
  holdsFor,
  keyOfState,
  READ_SUPERSEDED,
  sameKey,
  watch,
  type HostError,
  type ReadKey,
  type RefusedRequest,
  type Watch
} from '../../host/port'
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
  refusalTitle,
  refusalWords,
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

/** A host that does not answer, as the inbox draws it. */
interface Contact {
  readonly host: HostTag
  /** Since when contact has been lost, by this device's clock, when it is known. */
  readonly sinceMs: number | null
  /** When the loss reaches its next level, by this device's clock. */
  readonly escalatesAtMs: number | null
  /** When the rows listed for this host were read, while any are. */
  readonly rowsReadAtMs: number | null
}

/** A host that answered and refused a request of the visit, as the inbox draws it. */
interface Refusal {
  readonly host: HostTag
  /** What the visit asked when the host refused. */
  readonly request: RefusedRequest | null
  /** What the host refused with. */
  readonly refusal: HostError | null
}

/** No session numbers: a row then says "A session". */
const NO_NUMBERS: ReadonlyMap<string, string> = new Map()

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
  onOpenSession,
  onCounts
}: {
  readonly surface: Surface
  readonly onOpenSession: (sessionId: string) => void
  readonly onCounts?: (actionable: number) => void
}): ReactNode {
  const { port, say } = useApp()
  // What the host in use said, under the key the owner said it holds under: a read is stored only
  // while that is the key of the connection's latest state, and shown while the host and its epoch
  // still hold.
  const [inbox, setInbox] = useState<{
    readonly key: ReadKey
    readonly result: AttentionReadResult
    readonly atMs: number
  } | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [chosen, setChosen] = useState<AttentionFilter>('all')
  const [open, setOpen] = useState<HostedRow | null>(null)
  // Each session's display number, by its identifier, as the host in use listed them, under a key of
  // their own: a failed or differently keyed read of them leaves the inbox as it is.
  const [numbers, setNumbers] = useState<{
    readonly key: ReadKey
    readonly named: ReadonlyMap<string, string>
  } | null>(null)
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
          setError(null)
          return false
        },
        (failure: unknown) => {
          if (!current()) return false
          if (failureCode(failure) === READ_SUPERSEDED) return true
          // A host that cannot be read is a host out of contact, which is a state the inbox has.
          // It is never a claim that anything on it failed.
          setError(failureMessage(failure))
          return false
        }
      )
      const numbersRead = ask(() => port.sessionNumbers()).then(
        (answer) => {
          if (!current()) return
          const now = port.connectionLatest()
          if (now === null || !sameKey(answer.key, keyOfState(now))) return
          setNumbers({
            key: answer.key,
            named: new Map(answer.value.sessions.map((session) => [session.session_id, session.display_number]))
          })
        },
        () => undefined
      )
      return Promise.all([inboxRead, numbersRead]).then(([dropped]) => dropped)
    },
    [port]
  )

  const load = useCallback(async (): Promise<void> => {
    const current = reads.current?.read() ?? null
    if (current === null) return
    // A read that is dropped makes one new read from the connection's state as it stands then; a
    // second one that is dropped waits for the cadence.
    if (await readOnce(current)) await readOnce(current)
    if (current()) setNowMs(Date.now())
  }, [readOnce])

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

  // The host in use's rows are those read under the host and epoch the connection holds now. A
  // refusal moves the epoch, so a host that refused shows none.
  const latest = others.latest
  const here = inbox !== null && latest !== null && holdsFor(inbox.key, latest) ? inbox : null
  const numbered: ReadonlyMap<string, string> =
    numbers !== null && latest !== null && holdsFor(numbers.key, latest) ? numbers.named : NO_NUMBERS
  // Only a paired host in use has a name and a row of contact: the host on this computer has none.
  const inUseName = latest?.host?.kind === 'paired' ? latest.host.name : null
  const several = others.contacts.length > 0 || (others.hosts?.length ?? 0) > 0
  const inUse: HostTag = useMemo(
    () => ({ reference: null, name: inUseName ?? 'This host' }),
    [inUseName]
  )

  // Every host's rows, with the numbers its sessions go by and the host they are from.
  const hosted = useMemo<readonly HostedRow[]>(() => {
    const rows: HostedRow[] = []
    if (here !== null) {
      for (const row of order(here.result, here.atMs)) rows.push({ row, host: inUse, numbers: numbered })
    }
    for (const visit of others.hosts ?? []) {
      if (visit.result === null) continue
      const named = new Map(visit.sessions.map((each) => [each.session_id, each.display_number]))
      const host: HostTag = { reference: visit.reference, name: visit.name }
      for (const row of order(visit.result, visit.read_at_ms ?? nowMs)) {
        rows.push({ row, host, numbers: named })
      }
    }
    return orderAcrossHosts(rows)
  }, [here, inUse, numbered, others.hosts, nowMs])

  // The hosts that do not answer, and the hosts that answered and refused, both from the connection's
  // state: the host in use by its own contact, the others by the state's other hosts.
  const contacts = useMemo<readonly Contact[]>(() => {
    const lost: Contact[] = []
    if (latest !== null && inUseName !== null && latest.contact.state === 'out_of_contact') {
      lost.push({
        host: inUse,
        sinceMs: latest.contact.since_ms,
        escalatesAtMs: latest.contact.escalates_at_ms,
        rowsReadAtMs: here?.atMs ?? null
      })
    }
    for (const other of others.contacts) {
      if (other.contact.state !== 'out_of_contact') continue
      lost.push({
        host: { reference: other.reference, name: other.name },
        sinceMs: other.contact.since_ms,
        escalatesAtMs: other.contact.escalates_at_ms,
        rowsReadAtMs:
          others.hosts?.find((visit) => visit.reference === other.reference)?.read_at_ms ?? null
      })
    }
    return lost
  }, [latest, inUseName, inUse, here, others.hosts, others.contacts])

  // The level a loss has reached moves at the instant its state says, by one timer for each row.
  useEffect(() => {
    const timers = contacts.flatMap((each) => {
      if (each.escalatesAtMs === null) return []
      const wait = each.escalatesAtMs - Date.now()
      if (wait <= 0) return []
      return [
        setTimeout(() => {
          setNowMs(Date.now())
        }, wait)
      ]
    })
    return () => {
      for (const timer of timers) clearTimeout(timer)
    }
  }, [contacts])

  // A host that answered and refused is in contact, so it is not among the hosts out of contact, and
  // nothing of what it held before is listed.
  const refusals = useMemo<readonly Refusal[]>(() => {
    const refused: Refusal[] = []
    if (latest !== null && inUseName !== null && latest.contact.state === 'refused') {
      refused.push({ host: inUse, request: latest.contact.request, refusal: latest.contact.refusal })
    }
    for (const other of others.contacts) {
      if (other.contact.state !== 'refused') continue
      refused.push({
        host: { reference: other.reference, name: other.name },
        request: other.contact.request,
        refusal: other.contact.refusal
      })
    }
    return refused
  }, [latest, inUseName, inUse, others.contacts])

  const counts = useMemo(() => {
    let total = here === null ? NOTHING : count(here.result)
    for (const visit of others.hosts ?? []) {
      if (visit.result !== null) total = addCounts(total, count(visit.result))
    }
    return { ...total, disconnected: total.disconnected + contacts.length }
  }, [here, others.hosts, contacts])

  useEffect(() => {
    if (onCounts) onCounts(counts.actionable)
  }, [counts, onCounts])

  const notes = useMemo(() => (here ? inboxNotes(here.result) : []), [here])
  const shown = chosen === 'all' ? hosted : hosted.filter((each) => each.row.kind === chosen)
  const showContacts = chosen === 'all' || chosen === 'disconnected'
  // A refusal is no kind of item, and it hides what the host holds from every filter, so it is
  // told under every filter.
  const showRefusals = refusals.length > 0
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
  const inUseOut =
    contacts.some((each) => each.host.reference === null) ||
    refusals.some((each) => each.host.reference === null)

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
                data-level={each.escalatesAtMs !== null && nowMs >= each.escalatesAtMs ? 'urgent' : 'notable'}
                data-host={each.host.name}
                data-testid="inbox-contact"
                style={{ minBlockSize: target }}
              >
                <span className="m-row-head">
                  <span className="m-row-kind">{KIND_LABEL.disconnected}</span>
                  {each.escalatesAtMs !== null && nowMs >= each.escalatesAtMs ? (
                    <Badge tone="danger">Urgent</Badge>
                  ) : null}
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

      {showRefusals ? (
        <ul className="m-list" data-testid="inbox-refusals">
          {refusals.map((each) => (
            <li key={each.host.reference ?? 'in-use'}>
              <div
                className="m-row"
                data-tone="muted"
                data-kind="refused"
                data-host={each.host.name}
                data-refused={each.request ?? undefined}
                data-testid="inbox-refusal"
                style={{ minBlockSize: target }}
              >
                <span className="m-row-head">
                  <span className="m-row-kind">Refused</span>
                  <span className="m-row-where">{each.host.name}</span>
                </span>
                <span className="m-row-title">{refusalTitle(each.host.name, each.request)}</span>
                <span className="m-row-detail">{refusalWords(each.refusal)}</span>
              </div>
            </li>
          ))}
        </ul>
      ) : null}

      {shown.length === 0 && !(showContacts && contacts.length > 0) && !showRefusals ? (
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

