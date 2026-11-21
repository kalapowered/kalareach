/**
 * The drafts this device keeps that no composer shows.
 *
 * A draft is the person's own writing, so none is ever thrown away for them. Most live in the
 * composer of the session they were written for. These are the others: a draft whose session has
 * gone, one whose conversation changed so that a person has to say where it goes, one kept beside
 * another when two windows of the application changed the same draft, and a second draft of a
 * session whose composer holds one already. Each can be moved to a session the person chooses, or
 * discarded, and nothing here sends anything.
 *
 * Beneath them are the messages sent over a channel that confirms nothing, and the records of sends
 * that hold the next message to their session. The messages are shown whole and are never put in a
 * composer: the person reads and copies them, and removes what they no longer need.
 *
 * The list needs no host. Without one it shows, and discards, but it cannot offer a session to move a
 * draft to, and says so.
 */

import { useEffect, useState, type ReactNode } from 'react'

import type { SessionListResult } from '@kalareach/protocol'

import { useChannelMessages, useChannelShelf } from '../app/channel-messages'
import { useBook, useDraftBook } from '../app/drafts'
import { useApp } from '../app/state'
import { Banner, Button, CommitButton, TwoPressButton } from '../components/ui'
import { failureMessage, watch, type StoredChannelMessage, type StoredHold, type Watch } from '../host/port'
import { ask } from '../mobile/model/call'
import { MANY_HOLDS, nearlyFull, type ShelfSnapshot } from '../model/channel-messages'
import type { KeptDraft, KeptWhy } from '../model/draft-book'

type Session = SessionListResult['sessions'][number]

/** What could not be read, when a draft is listed because of it. */
export interface Unread {
  readonly messages: boolean
  readonly ledger: boolean
}

/** Why a draft is listed and not put in a composer by itself, when a place that can say it was sent could not be read. */
function unreadWords(unread: Unread): string {
  const what =
    unread.messages && unread.ledger
      ? 'its channel messages or its list of removals'
      : unread.ledger
        ? 'its list of removals'
        : 'its channel messages'
  return `This device could not read ${what}, so this draft is not put in a composer by itself. It can be a message that was sent.`
}

/** Why a draft is here, in words. */
function whyWords(why: KeptWhy, unread: Unread): string {
  switch (why) {
    case 'unread':
      return unreadWords(unread)
    case 'orphaned':
      return 'The session this was written for has gone.'
    case 'conflicted':
      return 'The conversation changed since this was written. Choose where it goes.'
    case 'copy':
      return 'Another window of this application changed this draft while you were writing in it, so what you wrote here is kept as its own draft.'
    case 'device':
      return 'Another device of yours wrote this draft. It is kept here, apart from your own, and nothing sends it.'
    case 'other':
      return 'This session’s composer holds a different draft.'
    case 'sent':
      return 'The host did not take this prompt, or could not say it did. It is kept so that nothing you wrote is lost.'
  }
}

/** How a session is named to a person: its number, and the directory it runs in. */
function sessionName(session: Session): string {
  return `Session ${session.display_number} · ${session.cwd}`
}

/**
 * How a draft's session is named: by its number and directory, as not listed when the host named
 * the sessions it has and this was not one, and as unknown when the host could not be asked.
 */
function homeLine(sessions: readonly Session[] | null, sessionId: string): string {
  if (sessions === null) return 'Its session cannot be listed now'
  const home = sessions.find((session) => session.session_id === sessionId)
  return home === undefined ? 'A session that is not listed' : sessionName(home)
}

/** The kept drafts, and what a person can do with each. */
export function KeptDrafts({
  onBack,
  phone = false
}: {
  readonly onBack?: () => void
  /** True on a phone, whose bar already names the screen and leaves it. */
  readonly phone?: boolean
}): ReactNode {
  const { port, say } = useApp()
  const book = useDraftBook()
  const { kept, status, problem, unreadable, unstored, ledger, sources } = useBook()
  const shelf = useChannelMessages()
  const channels = useChannelShelf()
  const [sessions, setSessions] = useState<readonly Session[] | null>(null)
  const [busy, setBusy] = useState<string | null>(null)

  // Where a draft can be moved is read once on opening. A host out of reach leaves the list empty,
  // and the screen says so; the drafts themselves are listed and can be discarded regardless.
  useEffect(() => {
    const reading: Watch = watch([], () => {
      const current = reading.read()
      if (current === null) return
      ask(() => port.sessionList({ environment_id: null, include_closed: false }))
        .then((result) => {
          if (!current()) return
          setSessions(result.sessions)
        })
        .catch(() => {
          if (!current()) return
          setSessions(null)
        })
    })
    return reading.stop
  }, [port])

  // The page reads the messages with their text while it is open.
  useEffect(() => {
    void channels.opened()
    return () => {
      channels.closed()
    }
  }, [channels])

  // Messages are unread when a read failed or a file could not be read now; the list of removals, when it is not `ok`.
  const unread: Unread = {
    ledger: ledger !== 'ok',
    messages:
      sources === 'unknown' &&
      (ledger === 'ok' || shelf.status === 'failed' || shelf.stale || shelf.unreadableMessages.now > 0)
  }

  const run = (id: string, step: () => Promise<void>, failed: string) => {
    setBusy(id)
    ask(step)
      .catch((error: unknown) => {
        say(`${failed}: ${failureMessage(error)}`, 'danger')
      })
      .finally(() => {
        setBusy(null)
      })
  }

  const stay =
    unstored.length === 0
      ? 'A draft stays on this device until you discard it, the host says the message it held was taken, or its text is kept in Channel messages. A message stays until you remove it. Nothing here is sent.'
      : 'A draft stays on this device until you discard it, the host says the message it held was taken, or its text is kept in Channel messages, except text held in this window only, which is lost when the application closes. A message stays until you remove it. Nothing here is sent.'
  const intro = 'Drafts that are not in a composer, and messages sent to Claude Code’s channel.'
  return (
    <>
      {phone ? (
        <p className="small muted">{intro} {stay}</p>
      ) : (
        <header className="page-heading">
          <div>
            <p className="eyebrow">Sessions</p>
            <h1>Kept drafts</h1>
            <p>{intro} {stay}</p>
          </div>
          {onBack === undefined ? null : (
            <div className="page-actions">
              <Button tone="quiet" data-testid="kept-drafts-back" onClick={onBack}>
                Back to sessions
              </Button>
            </div>
          )}
        </header>
      )}
      {status === 'memory-only' ? (
        <Banner
          tone="warning"
          title="This device is not keeping drafts"
          detail={`${problem ?? 'The place for them could not be opened.'} What you write is here, and it will not survive the application being closed.`}
          action={
            <Button
              data-testid="kept-drafts-retry"
              onClick={() => {
                void book.hydrate()
              }}
            >
              Try again
            </Button>
          }
        />
      ) : null}
      {unreadable === 0 ? null : (
        <Banner
          tone="warning"
          title="Some drafts could not be read"
          detail={`${unreadable === 1 ? 'One stored draft' : `${String(unreadable)} stored drafts`} could not be read by this version of the application. ${unreadable === 1 ? 'It was' : 'They were'} left as ${unreadable === 1 ? 'it is' : 'they are'}, and nothing was removed.`}
        />
      )}
      <ChannelBanners ledger={ledger} shelf={shelf} />
      {ledger === 'damaged' ? (
        <LedgerSetAside
          onSetAside={() => book.setLedgerAside()}
        />
      ) : null}
      {sessions === null && kept.length > 0 ? (
        <p className="small muted" data-testid="kept-drafts-offline">
          This device cannot ask the host which sessions there are, so a draft cannot be moved to
          another one now. They can still be read and discarded.
        </p>
      ) : null}
      {kept.length === 0 && unstored.length === 0 ? (
        <p className="muted" data-testid="kept-drafts-empty">
          No drafts are being kept apart.
        </p>
      ) : (
        <ul className="kept-drafts" data-testid="kept-drafts">
          {unstored.map((each) => {
            const home = sessions?.find((session) => session.session_id === each.sessionId) ?? null
            return (
              <li className="kept-draft" data-testid="unstored-prompt" key={each.id}>
                <p className="eyebrow">
                  {homeLine(sessions, each.sessionId)}
                  {' · '}held in this window only
                </p>
                <p className="small muted">
                  The host did not take this prompt, or could not say it did, and it is too long for
                  this device to keep as a draft. It is held in this window only and is lost when the
                  application closes.{' '}
                  {each.inComposer
                    ? ''
                    : home === null
                      ? 'Copy it before then.'
                      : 'Put it in its composer or copy it before then.'}{' '}
                  Check that the agent did not take it before you send it again.
                </p>
                {each.inComposer ? (
                  <p className="small muted" data-testid="unstored-prompt-copy">
                    A copy is in its composer. The device will not keep that copy either, so this one
                    stays listed until you remove it.
                  </p>
                ) : null}
                <pre className="kept-draft-text" data-testid="unstored-prompt-text" tabIndex={0}>
                  {each.text}
                </pre>
                <div className="row wrap">
                  {home === null || each.inComposer ? null : (
                    <Button
                      data-testid="unstored-prompt-use"
                      onClick={() => {
                        void book.useUnstored(each.id)
                      }}
                    >
                      Put it in its composer
                    </Button>
                  )}
                  <CommitButton
                    tone="quiet"
                    data-testid="unstored-prompt-forget"
                    onCommit={() => {
                      book.forgetUnstored(each.id)
                    }}
                  >
                    {each.inComposer ? 'Remove it from this list' : 'I have copied it'}
                  </CommitButton>
                </div>
              </li>
            )
          })}
          {kept.map((each) => (
            <KeptRow
              key={each.id}
              kept={each}
              sessions={sessions}
              unread={unread}
              busy={busy === each.id}
              onMove={(sessionId) => {
                run(each.id, () => book.moveTo(each.id, sessionId, each.revision), 'The draft was not moved')
              }}
              onUse={() => {
                run(each.id, () => book.useHere(each.id, each.revision), 'The draft was not put in its composer')
              }}
              onDiscard={() => {
                run(each.id, () => book.discard(each.id, each.revision), 'The draft was not discarded')
              }}
            />
          ))}
        </ul>
      )}
      <ChannelGroup
        shelf={shelf}
        sessions={sessions}
        busy={busy}
        onRemove={(id, removal) => {
          run(id, () => channels.remove(removal).then(() => undefined), 'The message was not removed')
        }}
        onClearHold={(holdId) => {
          run(`hold-${holdId}`, () => channels.clearHold(holdId), 'The record was not removed')
        }}
      />
    </>
  )
}

/** One kept draft. */
function KeptRow({
  kept,
  sessions,
  unread,
  busy,
  onMove,
  onUse,
  onDiscard
}: {
  readonly kept: KeptDraft
  readonly sessions: readonly Session[] | null
  readonly unread: Unread
  readonly busy: boolean
  readonly onMove: (sessionId: string) => void
  readonly onUse: () => void
  readonly onDiscard: () => void
}): ReactNode {
  const [choice, setChoice] = useState('')
  const home = sessions?.find((session) => session.session_id === kept.sessionId) ?? null
  const choices = (sessions ?? []).filter((session) => session.session_id !== kept.sessionId)
  return (
    <li className="kept-draft" data-testid="kept-draft" data-why={kept.why}>
      <p className="eyebrow">{homeLine(sessions, kept.sessionId)}</p>
      <p className="small muted" data-testid="kept-draft-why">
        {whyWords(kept.why, unread)}
      </p>
      {kept.unread && kept.why !== 'unread' ? (
        <p className="small muted" data-testid="kept-draft-unread">
          {unreadWords(unread)}
        </p>
      ) : null}
      <pre className="kept-draft-text" data-testid="kept-draft-text" tabIndex={0}>
        {kept.text.length === 0 ? '(no text)' : kept.text}
      </pre>
      {kept.files > 0 ? (
        <p className="small muted">
          {kept.files === 1 ? 'One file is kept with it.' : `${kept.files} files are kept with it.`}
        </p>
      ) : null}
      <div className="row wrap">
        {home !== null && !kept.inComposer ? (
          <Button data-testid="kept-draft-use" disabled={busy} onClick={onUse}>
            Put it in its composer
          </Button>
        ) : null}
        {choices.length > 0 ? (
          <>
            <label>
              <span className="visually-hidden">Move this draft to</span>
              <select
                value={choice}
                disabled={busy}
                data-testid="kept-draft-session"
                onChange={(event) => {
                  setChoice(event.target.value)
                }}
              >
                <option value="">Move to a session…</option>
                {choices.map((session) => (
                  <option key={session.session_id} value={session.session_id}>
                    {sessionName(session)}
                  </option>
                ))}
              </select>
            </label>
            <Button
              data-testid="kept-draft-move"
              disabled={busy || choice === ''}
              onClick={() => {
                onMove(choice)
              }}
            >
              Move it
            </Button>
          </>
        ) : null}
        <CommitButton tone="quiet" data-testid="kept-draft-discard" disabled={busy} onCommit={onDiscard}>
          Discard
        </CommitButton>
      </div>
    </li>
  )
}

/** What a person reads for files that could not be read: another layout of this application, or not now. */
function unreadableWords(count: { readonly layout: number; readonly now: number }, noun: 'message' | 'record'): string {
  const word = (n: number, kind: 'layout' | 'now'): string => {
    if (noun === 'message') {
      const things = n === 1 ? 'One stored message' : `${String(n)} stored messages`
      const left = n === 1 ? 'It was left as it is' : 'They were left as they are'
      return kind === 'layout'
        ? `${things} could not be read by this version of the application. ${left}, and nothing was removed.`
        : `${things} could not be read now. ${left}, and ${n === 1 ? 'it is' : 'they are'} read again later.`
    }
    const things = n === 1 ? 'A record of a message that was being sent' : `${String(n)} records of messages that were being sent`
    const left = n === 1 ? 'It was left as it is' : 'They were left as they are'
    return kind === 'layout'
      ? `${things} could not be read by this version of the application. ${left}. Check your sessions before you send again.`
      : `${things} could not be read now. Check your sessions before you send again.`
  }
  return [count.layout > 0 ? word(count.layout, 'layout') : '', count.now > 0 ? word(count.now, 'now') : '']
    .filter((each) => each !== '')
    .join(' ')
}

/** What was not read: the list of removals, the messages, the records of sends. */
function ChannelBanners({ ledger, shelf }: { readonly ledger: string; readonly shelf: ShelfSnapshot }): ReactNode {
  return (
    <>
      {ledger === 'ok' ? null : (
        <Banner
          tone="warning"
          title="The list of removals for drafts could not be read"
          detail={
            ledger === 'unreadable'
              ? 'It was left as it is, and it is read again later.'
              : 'It was left as it is, and nothing was removed.'
          }
        />
      )}
      {shelf.status === 'failed' || shelf.stale ? (
        <Banner
          tone="warning"
          title="Some channel messages could not be read"
          detail="The messages kept on this device could not be read now."
        />
      ) : null}
      {shelf.unreadableMessages.layout + shelf.unreadableMessages.now === 0 ? null : (
        <Banner
          tone="warning"
          title="Some channel messages could not be read"
          detail={unreadableWords(shelf.unreadableMessages, 'message')}
        />
      )}
      {shelf.unreadableHolds.layout + shelf.unreadableHolds.now === 0 ? null : (
        <Banner
          tone="warning"
          title="Some records of messages being sent could not be read"
          detail={unreadableWords(shelf.unreadableHolds, 'record')}
        />
      )}
    </>
  )
}

/** The control that sets a damaged list of removals aside. It shows for a damaged list and for no other. */
function LedgerSetAside({ onSetAside }: { readonly onSetAside: () => Promise<{ readonly moved: boolean; readonly confirmed: boolean }> }): ReactNode {
  const [note, setNote] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  return (
    <div className="kept-draft" data-testid="ledger-set-aside">
      <p className="small muted" data-testid="ledger-set-aside-why">
        The list of removals this device keeps for drafts is damaged and cannot be read. If you set it
        aside, this device stops reading it and rebuilds the removals that your kept channel messages
        name. The other removals in it are lost, so the text of a message that was sent or kept can come
        back as a draft, in its session’s composer or on this page. Nothing sends it by itself. The old
        list is kept in a file of its own, not deleted.
      </p>
      <div className="row wrap">
        <TwoPressButton
          tone="quiet"
          data-testid="ledger-set-aside-button"
          armedLabel="Press again to set the list aside"
          disabled={busy}
          onCommit={() => {
            setBusy(true)
            setNote(null)
            ask(onSetAside)
              .then((done) => {
                if (done.moved && !done.confirmed) {
                  setNote('The list was set aside, but this device could not confirm that on disk yet.')
                }
              })
              .catch(() => {
                setNote('This device could not set the list aside. The original list is still in place.')
              })
              .finally(() => {
                setBusy(false)
              })
          }}
        >
          Set the list aside
        </TwoPressButton>
      </div>
      {note === null ? null : (
        <p className="small" role="alert" data-testid="ledger-set-aside-note">
          {note}
        </p>
      )}
    </div>
  )
}

/** When a record or message was written, as a person reads a time. */
function whenWords(ms: string): string {
  const at = new Date(Number(ms))
  return Number.isNaN(at.getTime()) ? 'an unknown time' : at.toLocaleString()
}

/** A session's line inside a sentence: its first letter is lower-case when it begins "A session" or "Its session". */
function sessionPhrase(line: string): string {
  return /^(A|Its) session/.test(line) ? `${line.charAt(0).toLowerCase()}${line.slice(1)}` : line
}

/** The messages, the records of sends, and the ones that could not be read, below the drafts. */
function ChannelGroup({
  shelf,
  sessions,
  busy,
  onRemove,
  onClearHold
}: {
  readonly shelf: ShelfSnapshot
  readonly sessions: readonly Session[] | null
  readonly busy: string | null
  readonly onRemove: (id: string, removal: { readonly actionId: string } | { readonly sessionId: string }) => void
  readonly onClearHold: (holdId: string) => void
}): ReactNode {
  const bySession = new Map<string, StoredChannelMessage[]>()
  for (const message of shelf.messages) {
    bySession.set(message.sessionId, [...(bySession.get(message.sessionId) ?? []), message])
  }
  const holdsShown = shelf.holds.length > 0 || shelf.damagedHolds.length > 0
  return (
    <>
      {shelf.messages.length === 0 && !nearlyFull(shelf) ? null : (
        <section className="channel-messages" data-testid="channel-messages">
          <h2>Channel messages</h2>
          {shelf.messages.length === 0 ? null : (
            <p className="small muted">
              When these were sent, Claude Code did not confirm the messages it takes, so the host could not
              tell whether they arrived. They stay on this device until you remove them, and nothing here
              sends them.
            </p>
          )}
          {nearlyFull(shelf) ? (
            <p className="small" data-testid="channel-messages-full">
              Channel messages is nearly full. Remove the messages you do not need.
            </p>
          ) : null}
          <ul className="kept-drafts">
            {[...bySession.entries()].map(([sessionId, messages]) => (
              <li className="kept-draft" data-testid="channel-session" key={sessionId}>
                {messages.length > 1 ? (
                  <div className="row wrap">
                    <p className="eyebrow">{homeLine(sessions, sessionId)}</p>
                    <TwoPressButton
                      tone="quiet"
                      data-testid="channel-session-remove-all"
                      armedLabel="Press again to remove all"
                      disabled={busy === `session-${sessionId}`}
                      onCommit={() => {
                        onRemove(`session-${sessionId}`, { sessionId })
                      }}
                    >
                      Remove all
                    </TwoPressButton>
                  </div>
                ) : null}
                <ul>
                  {messages.map((message) => (
                    <ChannelMessageRow
                      key={message.actionId}
                      message={message}
                      sessions={sessions}
                      readFailed={shelf.stale}
                      busy={busy === message.actionId}
                      onRemove={() => {
                        onRemove(message.actionId, { actionId: message.actionId })
                      }}
                    />
                  ))}
                </ul>
              </li>
            ))}
          </ul>
        </section>
      )}
      {holdsShown ? (
        <section className="channel-holds" data-testid="channel-holds">
          <h2>Records of messages being sent</h2>
          {shelf.holds.length >= MANY_HOLDS ? (
            <p className="small" data-testid="channel-holds-many">
              This device keeps many records of messages it has not settled. Each one can hold the next
              message to its session. Remove the records of sessions you no longer use.
            </p>
          ) : null}
          <ul className="kept-drafts">
            {shelf.holds.map((hold) => (
              <ChannelHoldRow
                key={hold.holdId}
                hold={hold}
                sessions={sessions}
                busy={busy === `hold-${hold.holdId}`}
                onClear={() => {
                  onClearHold(hold.holdId)
                }}
              />
            ))}
            {shelf.damagedHolds.map((name) => (
              <li className="kept-draft" data-testid="channel-hold-damaged" key={name}>
                <p className="eyebrow">{name}</p>
                <p className="small muted">
                  This device cannot read this record of a message that was being sent. It holds every
                  message to a channel session. Removing it sends nothing.
                </p>
                <div className="row wrap">
                  <TwoPressButton
                    tone="quiet"
                    data-testid="channel-hold-damaged-remove"
                    armedLabel="Press again to remove"
                    disabled={busy === `hold-${name}`}
                    onCommit={() => {
                      onClearHold(name)
                    }}
                  >
                    Remove
                  </TwoPressButton>
                </div>
              </li>
            ))}
          </ul>
        </section>
      ) : null}
    </>
  )
}

/** One message sent over a channel that confirms nothing, with its whole text. */
function ChannelMessageRow({
  message,
  sessions,
  readFailed,
  busy,
  onRemove
}: {
  readonly message: StoredChannelMessage
  readonly sessions: readonly Session[] | null
  /** True when the newest read of the shelf failed. */
  readonly readFailed: boolean
  readonly busy: boolean
  readonly onRemove: () => void
}): ReactNode {
  return (
    <li className="kept-draft" data-testid="channel-message">
      <p className="eyebrow">
        {homeLine(sessions, message.sessionId)}
        {' · '}
        {message.hostName}
      </p>
      <p className="small muted">
        Sent at {whenWords(message.sentAtMs)}. When this was sent, the host could not tell whether Claude
        Code took it. Check the session before you send it again.
      </p>
      {message.text !== undefined ? (
        <pre className="kept-draft-text" data-testid="channel-message-text" tabIndex={0}>
          {message.text}
        </pre>
      ) : readFailed ? (
        <p className="small" data-testid="channel-message-text-unavailable">
          This device could not read the text of this message now.
        </p>
      ) : null}
      <div className="row wrap">
        <TwoPressButton
          tone="quiet"
          data-testid="channel-message-remove"
          armedLabel="Press again to remove"
          disabled={busy}
          onCommit={onRemove}
        >
          Remove
        </TwoPressButton>
      </div>
    </li>
  )
}

/** One record of a send, which holds the next message to its session until the host says what became of it. */
function ChannelHoldRow({
  hold,
  sessions,
  busy,
  onClear
}: {
  readonly hold: StoredHold
  readonly sessions: readonly Session[] | null
  readonly busy: boolean
  readonly onClear: () => void
}): ReactNode {
  return (
    <li className="kept-draft" data-testid="channel-hold">
      <p className="small muted">
        A message to {sessionPhrase(homeLine(sessions, hold.sessionId))} on {hold.hostName}, pressed at{' '}
        {whenWords(hold.sentAtMs)}. This device has not settled what became of it. Removing this record
        sends nothing.
      </p>
      <div className="row wrap">
        <TwoPressButton
          tone="quiet"
          data-testid="channel-hold-remove"
          armedLabel="Press again to remove"
          disabled={busy}
          onCommit={onClear}
        >
          Remove
        </TwoPressButton>
      </div>
    </li>
  )
}
