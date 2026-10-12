/**
 * The path each attached file can be read at on the host.
 *
 * A prompt sent from a draft carries its text only, so a file on the draft is not sent to the
 * agent: the person gives the agent its path themselves, in the agent's terminal. The host gives the
 * path for a short while, and the path is not quoted for any shell, so the person quotes it for
 * theirs. The path is text on the screen that can be selected and copied.
 */

import { useEffect, useState, useSyncExternalStore, type ReactNode } from 'react'

import { useApp } from '../app/state'
import type { SessionSubject } from '../host/port'
import type { DraftAttachment } from '../model/drafts'
import type { PathState } from '../model/manual-paths'
import { Button } from './ui'

/**
 * True once `at` has passed, and the page is told when that happens.
 *
 * The clock is read when the screen opens and again when `at` comes, which is a moment after the
 * screen first shows a path, so a path that was given already past its time shows as expired as
 * soon as that moment arrives.
 */
function usePassed(at: number | null): boolean {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    if (at === null) return
    const timer = setTimeout(
      () => {
        setNow(Date.now())
      },
      // A timer cannot be set past 2^31 - 1 milliseconds.
      Math.min(Math.max(at - Date.now(), 0) + 20, 2_147_483_647)
    )
    return () => {
      clearTimeout(timer)
    }
  }, [at])
  return at !== null && at <= now
}

/** The time of day a path stops being valid. */
function untilWords(at: number): string {
  return new Date(at).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' })
}

/** One file's path, and what to do when it has none. */
function FilePath({
  attachment,
  sessionId,
  state,
  onAsk,
  target
}: {
  readonly attachment: DraftAttachment
  readonly sessionId: string
  readonly state: PathState | undefined
  readonly onAsk: () => void
  readonly target: number | undefined
}): ReactNode {
  const expiresAt = state?.kind === 'ready' ? state.expiresAtMs : null
  const expired = usePassed(expiresAt)
  const size = target === undefined ? undefined : { minBlockSize: target }
  const ask = (label: string) => (
    <Button data-testid="attachment-path-ask" style={size} onClick={onAsk}>
      {label}
    </Button>
  )
  // A file sent for another session has no path here, whatever a path it was given before says.
  const elsewhere =
    attachment.handle?.session_id != null && attachment.handle.session_id !== sessionId
  return (
    <li
      className="attachment-path"
      data-testid="attachment-path-row"
      data-path={elsewhere ? 'elsewhere' : (state?.kind ?? 'none')}
    >
      <p className="eyebrow">{attachment.name}</p>
      {elsewhere ? (
        <p className="small" data-testid="attachment-path-refusal">
          This file was sent for another session. Take it off the draft and attach it again here.
        </p>
      ) : state === undefined ? (
        <>
          <p className="small muted">This file has no path on the host yet.</p>
          {ask('Get its path')}
        </>
      ) : state.kind === 'binding' ? (
        <p className="small muted" role="status">
          Asking the host for its path…
        </p>
      ) : state.kind === 'refused' ? (
        <>
          <p className="small" data-testid="attachment-path-refusal">
            {state.words}
          </p>
          {ask('Try again')}
        </>
      ) : state.kind === 'unconfirmed' ? (
        <>
          <p className="small" data-testid="attachment-path-refusal">
            The host did not say whether it gave this file a path, and nothing was assumed.
          </p>
          {ask('Try again')}
        </>
      ) : expired ? (
        <>
          <p className="small" data-testid="attachment-path-refusal">
            The path the host gave for this file has expired.
          </p>
          {ask('Get a new path')}
        </>
      ) : (
        <>
          <code className="attachment-path-text" data-testid="attachment-path" tabIndex={0}>
            {state.hostPath}
          </code>
          <p className="small muted">
            This is where the file is on the host. Give the path to your agent yourself, in its
            terminal. It is not quoted for any shell, so quote it for yours. It is good until{' '}
            {untilWords(state.expiresAtMs)}.
          </p>
        </>
      )}
    </li>
  )
}

/** The paths of the files on a draft that have been sent to the host. */
export function AttachmentPaths({
  sessionId,
  subject,
  attachments,
  target
}: {
  readonly sessionId: string
  /**
   * What the request names: the session, with its epoch. A screen that does not hold the epoch gives
   * a function that asks the host for it, which is called when a path is asked for.
   */
  readonly subject: SessionSubject | (() => Promise<SessionSubject>)
  readonly attachments: readonly DraftAttachment[]
  /** The smallest height of a control a finger presses, on a phone. */
  readonly target?: number
}): ReactNode {
  const { paths } = useApp()
  const states = useSyncExternalStore(paths.subscribe, paths.snapshot)
  const sent = attachments.filter(
    (attachment) => attachment.upload === 'uploaded' && attachment.handle !== null
  )
  if (sent.length === 0) return null
  return (
    <ul className="attachment-paths" data-testid="attachment-paths">
      {sent.map((attachment) => (
        <FilePath
          key={attachment.localId}
          attachment={attachment}
          sessionId={sessionId}
          state={attachment.transferId === null ? undefined : states.get(attachment.transferId)}
          target={target}
          onAsk={() => {
            const handle = attachment.handle
            if (handle === null) return
            void paths.attach(sessionId, subject, handle)
          }}
        />
      ))}
    </ul>
  )
}
