/**
 * The confirmations this computer's hosts ask for, at the head of Attention.
 *
 * A host this computer owns asks its owner devices to confirm sensitive actions. Native code finds
 * them, checks each against what it would authorise, and sends this page descriptions only. The
 * button is named for this computer's own ceremony, and pressing it asks native code to review the
 * request: the platform's dialog then asks the person, and nothing here can answer it. A computer
 * with no ceremony says where to confirm instead, and a request that could not be checked says so
 * and offers nothing to press.
 */

import {
  useCallback,
  useEffect,
  useRef,
  useState,
  useSyncExternalStore,
  type ReactNode
} from 'react'

import { Button, CommitButton } from '../components/ui'
import { useApp } from '../app/state'
import {
  failureMessage,
  type CeremonyKind,
  type ConfirmationRequest,
  type ReviewOutcome
} from '../host/port'
import { SpelledValue } from './VerificationValue'
import { secondsLeft } from './words'

/** How long a row that has gone stays on screen while it fades. */
const LEAVING_MS = 120

/** The confirm button's name, for the ceremony this computer offers. */
export function confirmLabel(ceremony: CeremonyKind): string | null {
  switch (ceremony) {
    case 'touch_id':
      return 'Confirm with Touch ID'
    case 'password':
      return 'Confirm with your password'
    case 'windows_hello':
      return 'Confirm with Windows Hello'
    case 'none':
      return null
  }
}

/** What the person is told once a review ends. */
function outcomeWords(outcome: ReviewOutcome, host: string): string {
  switch (outcome) {
    case 'confirmed':
      return `Confirmed. ${host} can go ahead.`
    case 'not_confirmed':
      return 'Not confirmed. Nothing changed.'
    case 'expired':
      return 'That request expired before it was confirmed.'
    case 'cannot_check':
      return 'This request could not be checked, so it cannot be confirmed here.'
    case 'no_ceremony':
      return 'This computer cannot check it is you. Confirm on your phone.'
    case 'unknown':
      return `${host} did not say whether it took the confirmation. While the request is listed here, it is not confirmed.`
  }
}

/** How a review's outcome is shown: done, not known yet, or not done. */
function outcomeTone(outcome: ReviewOutcome): 'success' | 'pending' | 'danger' {
  switch (outcome) {
    case 'confirmed':
      return 'success'
    case 'unknown':
      return 'pending'
    default:
      return 'danger'
  }
}

/** The confirmations this computer's hosts ask for, as every screen reads them. */
export function useConfirmations(): {
  readonly ceremony: CeremonyKind
  readonly requests: readonly ConfirmationRequest[]
} | null {
  const { confirmations } = useApp()
  const { view, shown } = useSyncExternalStore(confirmations.subscribe, confirmations.current)
  return view === null ? null : { ceremony: view.ceremony, requests: shown }
}

/** A row, and whether it is leaving. */
interface Row {
  readonly request: ConfirmationRequest
  readonly leaving: boolean
}

/** The rows for `shown`, after `before`: each keeps its place, and those that went are leaving. */
function arrange(before: readonly Row[], shown: readonly ConfirmationRequest[]): readonly Row[] {
  const current = new Map(shown.map((request) => [request.reference, request]))
  const kept = before.map((row) => {
    const now = current.get(row.request.reference)
    return now === undefined ? { request: row.request, leaving: true } : { request: now, leaving: false }
  })
  const drawn = new Set(before.map((row) => row.request.reference))
  const arrived = shown
    .filter((request) => !drawn.has(request.reference))
    .map((request) => ({ request, leaving: false }))
  return [...kept, ...arrived]
}

/**
 * The rows for `shown`, and those that just went, each fading in its own place for
 * {@link LEAVING_MS} before it is taken off. A row keeps its identity while it leaves, and its
 * removal is its own: later changes neither cancel nor restart it.
 */
function useRows(shown: readonly ConfirmationRequest[]): readonly Row[] {
  const [rows, setRows] = useState<readonly Row[]>(() =>
    shown.map((request) => ({ request, leaving: false }))
  )
  const [drawnFrom, setDrawnFrom] = useState(shown)
  if (drawnFrom !== shown) {
    setDrawnFrom(shown)
    setRows((before) => arrange(before, shown))
  }
  const removals = useRef(new Map<string, ReturnType<typeof setTimeout>>())
  useEffect(() => {
    const pending = removals.current
    for (const { request, leaving } of rows) {
      const removal = pending.get(request.reference)
      if (leaving && removal === undefined) {
        pending.set(
          request.reference,
          setTimeout(() => {
            pending.delete(request.reference)
            setRows((before) =>
              before.filter((row) => !(row.leaving && row.request.reference === request.reference))
            )
          }, LEAVING_MS)
        )
      } else if (!leaving && removal !== undefined) {
        // It came back before it was taken off.
        clearTimeout(removal)
        pending.delete(request.reference)
      }
    }
  }, [rows])
  useEffect(() => {
    const pending = removals.current
    return () => {
      for (const removal of pending.values()) clearTimeout(removal)
    }
  }, [])
  return rows
}

/** The requests, as rows. */
export function Confirmations(): ReactNode {
  const { port, say, confirmations } = useApp()
  const { view, shown, focusing } = useSyncExternalStore(
    confirmations.subscribe,
    confirmations.current
  )
  const rows = useRows(shown)
  const [reviewing, setReviewing] = useState<string | null>(null)
  const [now, setNow] = useState(() => Date.now())
  const placed = useRef(new Map<string, HTMLLIElement>())

  // A request a "Review" asked for takes focus once its row is drawn, so a screen reader reads it
  // and the next Tab reaches its buttons.
  useEffect(() => {
    if (focusing === null) return
    const row = placed.current.get(focusing)
    if (row === undefined) return
    row.focus()
    confirmations.focused()
  }, [focusing, rows, confirmations])

  const counting = shown.length > 0
  useEffect(() => {
    if (!counting) return
    const tick = setInterval(() => {
      setNow(Date.now())
    }, 1000)
    return () => {
      clearInterval(tick)
    }
  }, [counting])

  const review = useCallback(
    (request: ConfirmationRequest) => {
      setReviewing(request.reference)
      port
        .ownerConfirmationReview(request.reference)
        .then((outcome) => {
          say(outcomeWords(outcome, request.host_name), outcomeTone(outcome))
        })
        .catch((error: unknown) => {
          say(failureMessage(error), 'danger')
        })
        .finally(() => {
          setReviewing(null)
        })
    },
    [port, say]
  )

  if (view === null || rows.length === 0) return null
  const label = confirmLabel(view.ceremony)

  return (
    <section aria-labelledby="owner-confirmations" className="confirmations" data-testid="confirmations">
      <h2 id="owner-confirmations">Your hosts need your confirmation</h2>
      <ul className="confirmation-list">
        {rows.map(({ request, leaving }) => (
          <li
            key={request.reference}
            ref={(row) => {
              if (row === null) placed.current.delete(request.reference)
              else placed.current.set(request.reference, row)
            }}
            className="confirmation-row"
            data-testid="confirmation-row"
            data-leaving={leaving ? 'true' : undefined}
            inert={leaving}
            tabIndex={-1}
            aria-labelledby={`confirmation-${request.reference}`}
          >
            <div className="spacer">
              <p className="confirmation-title" id={`confirmation-${request.reference}`}>
                <strong>{request.title}</strong>
                <span className="small muted"> · {request.host_name}</span>
              </p>
              {request.detail !== null ? <p className="small">{request.detail}</p> : null}
              {request.value !== null ? (
                <p className="small" data-testid="confirmation-value">
                  It should show <SpelledValue value={request.value} />.
                </p>
              ) : null}
              {!request.checkable ? (
                <p className="small warning-text" data-testid="cannot-check">
                  This request could not be checked, so it cannot be confirmed here.
                </p>
              ) : label === null ? (
                <p className="small muted" data-testid="no-ceremony">
                  Confirm this on your phone, or on another device that can check it is you.
                </p>
              ) : null}
            </div>
            <div className="confirmation-actions">
              <span className="small muted tabular">{secondsLeft(request.expires_at_ms, now)}</span>
              {request.checkable && label !== null ? (
                <CommitButton
                  tone="primary"
                  data-testid="confirm-request"
                  disabled={reviewing !== null}
                  onCommit={() => {
                    review(request)
                  }}
                >
                  {label}
                </CommitButton>
              ) : null}
              <Button
                tone="quiet"
                data-testid="not-now"
                onClick={() => {
                  confirmations.setAside(request)
                }}
              >
                Not now
              </Button>
            </div>
          </li>
        ))}
      </ul>
    </section>
  )
}
