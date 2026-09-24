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

import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react'

import { Button, CommitButton } from '../components/ui'
import { useApp } from '../app/state'
import {
  failureMessage,
  type CeremonyKind,
  type ConfirmationRequest,
  type OwnerView,
  type ReviewOutcome
} from '../host/port'
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
  }
}

/** The confirmations this computer's hosts ask for, kept current. */
export function useConfirmations(): OwnerView | null {
  const { port } = useApp()
  const [view, setView] = useState<OwnerView | null>(null)
  useEffect(() => {
    let watching = true
    // An event is newer than the first read, so a read that answers after one is let go.
    let heard = false
    port
      .ownerConfirmations()
      .then((current) => {
        if (watching && !heard) setView(current)
      })
      .catch(() => {
        // A computer that cannot pair has no confirmations to show.
      })
    const stop = port.onConfirmations((next) => {
      heard = true
      setView(next)
    })
    return () => {
      watching = false
      stop()
    }
  }, [port])
  return view
}

/** The requests, as rows. */
export function Confirmations(): ReactNode {
  const { port, say } = useApp()
  const view = useConfirmations()
  const [hidden, setHidden] = useState<ReadonlySet<string>>(new Set())
  const [leaving, setLeaving] = useState<readonly ConfirmationRequest[]>([])
  const [reviewing, setReviewing] = useState<string | null>(null)
  const [now, setNow] = useState(() => Date.now())
  const shown = useRef<ReadonlyMap<string, ConfirmationRequest>>(new Map())
  const announced = useRef<Set<string>>(new Set())

  // A row that went away fades before it is taken off, and a new one is announced once.
  useEffect(() => {
    if (view === null) return
    const current = new Map(view.requests.map((request) => [request.reference, request]))
    const gone = [...shown.current.values()].filter(
      (request) => !current.has(request.reference)
    )
    shown.current = current
    for (const request of view.requests) {
      if (!announced.current.has(request.reference)) {
        announced.current.add(request.reference)
        say(`${request.host_name} needs your confirmation`, 'pending')
      }
    }
    if (gone.length === 0) return
    setLeaving((before) => [...before, ...gone])
    const taken = setTimeout(() => {
      setLeaving((before) => before.filter((request) => !gone.includes(request)))
    }, LEAVING_MS)
    return () => {
      clearTimeout(taken)
    }
  }, [view, say])

  const counting = (view?.requests.length ?? 0) > 0
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
          say(outcomeWords(outcome, request.host_name), outcome === 'confirmed' ? 'success' : 'danger')
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

  if (view === null) return null
  const rows = view.requests.filter((request) => !hidden.has(request.reference))
  if (rows.length === 0 && leaving.length === 0) return null
  const label = confirmLabel(view.ceremony)

  return (
    <section aria-labelledby="owner-confirmations" className="confirmations" data-testid="confirmations">
      <h2 id="owner-confirmations">Your hosts need your confirmation</h2>
      <ul className="confirmation-list">
        {rows.map((request) => (
          <li key={request.reference} className="confirmation-row" data-testid="confirmation-row">
            <div className="spacer">
              <p className="confirmation-title">
                <strong>{request.title}</strong>
                <span className="small muted"> · {request.host_name}</span>
              </p>
              {request.detail !== null ? <p className="small">{request.detail}</p> : null}
              {request.value !== null ? (
                <p className="small">
                  It should show <span className="mono tabular">{request.value}</span>.
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
                  setHidden((before) => new Set([...before, request.reference]))
                }}
              >
                Not now
              </Button>
            </div>
          </li>
        ))}
        {leaving.map((request) => (
          <li
            key={`leaving-${request.reference}`}
            className="confirmation-row"
            data-leaving="true"
            aria-hidden="true"
          >
            <div className="spacer">
              <p className="confirmation-title">
                <strong>{request.title}</strong>
              </p>
            </div>
          </li>
        ))}
      </ul>
    </section>
  )
}
