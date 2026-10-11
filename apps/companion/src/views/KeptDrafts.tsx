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
 * The list needs no host. Without one it shows, and discards, but it cannot offer a session to move a
 * draft to, and says so.
 */

import { useEffect, useState, type ReactNode } from 'react'

import type { SessionListResult } from '@kalareach/protocol'

import { useBook, useDraftBook } from '../app/drafts'
import { useApp } from '../app/state'
import { Banner, Button, CommitButton } from '../components/ui'
import { failureMessage, watch, type Watch } from '../host/port'
import { ask } from '../mobile/model/call'
import type { KeptDraft, KeptWhy } from '../model/draft-book'

type Session = SessionListResult['sessions'][number]

/** Why a draft is here, in words. */
function whyWords(why: KeptWhy): string {
  switch (why) {
    case 'orphaned':
      return 'The session this was written for has gone.'
    case 'conflicted':
      return 'The conversation changed since this was written. Choose where it goes.'
    case 'copy':
      return 'Another window of this application changed this draft while you were writing in it, so what you wrote here is kept as its own draft.'
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
  const { kept, status, problem, unreadable, unstored } = useBook()
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
      ? 'They stay on this device until you discard them, and nothing here is sent.'
      : 'They stay on this device until you discard them, except text held in this window only, which is lost when the application closes. Nothing here is sent.'
  return (
    <>
      {phone ? (
        <p className="small muted">Drafts that are not in a composer. {stay}</p>
      ) : (
        <header className="page-heading">
          <div>
            <p className="eyebrow">Sessions</p>
            <h1>Kept drafts</h1>
            <p>Drafts that are not in a composer. {stay}</p>
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
    </>
  )
}

/** One kept draft. */
function KeptRow({
  kept,
  sessions,
  busy,
  onMove,
  onUse,
  onDiscard
}: {
  readonly kept: KeptDraft
  readonly sessions: readonly Session[] | null
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
        {whyWords(kept.why)}
      </p>
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
