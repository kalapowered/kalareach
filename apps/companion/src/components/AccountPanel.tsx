/**
 * The account panel: the phone's Account screen and the body of the desktop's Account sheet.
 *
 * One panel for both, so both say the same thing in the same states. Signing in hands the passkey
 * ceremony to the system browser on reach.kala.to; the panel asks the backend to start it and is
 * told where the device stands. It never holds the address the browser opens, and it names the
 * origin as text, never as a link.
 *
 * Signing in happens about once a month per device and the person's attention is in the browser
 * while it does, so nothing here is decorative. A change of state fades in over the existing state
 * duration with no travel, which reduced motion needs no second version of, and the keyboard rule
 * makes it instant. There is no spinner while the browser is open, because the application is
 * waiting for the person rather than working; a small indicator joins "Signing in…" only when the
 * exchange passes 400 ms, so a fast one never flashes it.
 *
 * Nothing to buy: no plan, no price, no balance, no link and no form. Usage is figures and meters.
 */

import { useCallback, useEffect, useId, useRef, useState, type ReactNode } from 'react'

import type { HostPort } from '../host/port'
import { minimumTarget, type Surface } from '../mobile/platform'
import {
  SIGN_IN_HELP,
  describeAccount,
  describeOutcome,
  describeUnavailable,
  describeUsage,
  usageFraction,
  type AccountView,
  type UsageView
} from '../model/account'
import { Button, Card } from './ui'

/** The account, read from the backend and kept current. */
export interface AccountHandle {
  readonly view: AccountView | null
  readonly usage: UsageView | null
  readonly signIn: () => void
  readonly cancel: () => void
  readonly signOut: () => void
  readonly readUsage: () => void
}

/** Reads where the device stands and follows every change the backend publishes. */
export function useAccount(port: HostPort): AccountHandle {
  const [view, setView] = useState<AccountView | null>(null)
  const [usage, setUsage] = useState<UsageView | null>(null)

  useEffect(() => {
    let live = true
    port
      .accountStatus()
      .then((next) => {
        if (live) setView(next)
      })
      .catch(() => {
        if (live) setView({ state: 'signed_out', outcome: null })
      })
    const stop = port.onAccount((next) => {
      if (live) setView(next)
    })
    return () => {
      live = false
      stop()
    }
  }, [port])

  const readUsage = useCallback(() => {
    port
      .accountUsage()
      .then(setUsage)
      .catch(() => {
        setUsage({ state: 'could_not_read' })
      })
  }, [port])

  const readable = view?.state === 'signed_in' && view.usage_readable
  useEffect(() => {
    if (readable) readUsage()
  }, [readable, readUsage])

  const signIn = useCallback(() => {
    // The panel says the browser is open before the browser appears, so a return by any path lands
    // on a screen that says what happens next.
    setView({ state: 'browser_open' })
    port
      .accountSignIn()
      .then(setView)
      .catch(() => {
        setView({ state: 'signed_out', outcome: 'browser_failed' })
      })
  }, [port])

  const cancel = useCallback(() => {
    void port.accountSignInCancel().catch(() => undefined)
  }, [port])

  const signOut = useCallback(() => {
    port
      .accountSignOut()
      .then(setView)
      .catch(() => {
        setView({ state: 'signed_out', outcome: 'sign_out_failed' })
      })
  }, [port])

  // Usage is shown only while the sign-in may read it.
  return { view, usage: readable ? usage : null, signIn, cancel, signOut, readUsage }
}

/** The account panel. */
export function AccountPanel({
  account,
  surface
}: {
  readonly account: AccountHandle
  readonly surface: Surface
}): ReactNode {
  const { view, usage } = account
  const target = minimumTarget(surface)
  const helpId = useId()
  const statusRef = useRef<HTMLDivElement | null>(null)
  const cancelRef = useRef<HTMLButtonElement | null>(null)
  const previous = useRef<AccountView['state'] | null>(null)

  // While the browser is open, Cancel is the first control. On the way back, focus goes to the
  // status line, so VoiceOver and TalkBack read how the attempt ended.
  useEffect(() => {
    const before = previous.current
    previous.current = view?.state ?? null
    if (!view) return
    if (view.state === 'browser_open') {
      cancelRef.current?.focus()
      return
    }
    if (before === 'browser_open' || before === 'finishing') {
      statusRef.current?.focus()
    }
  }, [view])

  if (!view) {
    return <div className="account-panel" data-testid="account-panel" aria-busy="true" />
  }

  const outcome = view.state === 'signed_out' ? view.outcome : null
  const offersSignIn = view.state === 'signed_out' || view.state === 'ended'

  return (
    <div className="account-panel" data-testid="account-panel">
      <Card>
        <div className="account-state" key={view.state}>
          <div className="account-status" role="status" tabIndex={-1} ref={statusRef}>
            <p className="account-lead">
              {describeAccount(view)}
              {view.state === 'finishing' ? <Working /> : null}
            </p>
            {view.state === 'unavailable' ? (
              <p className="account-note">{describeUnavailable(view.reason)}</p>
            ) : null}
            {outcome ? <p className="account-note">{describeOutcome(outcome)}</p> : null}
          </div>
          {offersSignIn ? (
            <div className="account-actions">
              <Button
                tone="primary"
                style={{ minBlockSize: target }}
                aria-describedby={helpId}
                onClick={account.signIn}
              >
                Sign in
              </Button>
              <p className="account-help" id={helpId}>
                {SIGN_IN_HELP}
              </p>
            </div>
          ) : null}
          {view.state === 'browser_open' ? (
            <div className="account-actions">
              <button
                type="button"
                className="btn"
                ref={cancelRef}
                style={{ minBlockSize: target }}
                onClick={account.cancel}
              >
                Cancel
              </button>
            </div>
          ) : null}
          {view.state === 'signed_in' ? (
            <div className="account-actions">
              <Button style={{ minBlockSize: target }} onClick={account.signOut}>
                Sign out
              </Button>
            </div>
          ) : null}
        </div>
      </Card>

      {view.state === 'signed_in' ? (
        <Usage
          readable={view.usage_readable}
          usage={usage}
          target={target}
          onRetry={account.readUsage}
        />
      ) : null}

      <p className="account-section-title">Working without an account</p>
      <Card>
        <p className="account-note">
          Your hosts run on your machines. Sessions, agents and terminals work the same whether this
          device is signed in or not, and nothing here needs an account to reach a host you paired.
        </p>
      </Card>
    </div>
  )
}

/**
 * The small indicator beside "Signing in…". It appears only once the exchange has taken 400 ms,
 * so a fast one never flashes it, and it starts afresh each time the panel is finishing.
 */
function Working(): ReactNode {
  const [shown, setShown] = useState(false)
  useEffect(() => {
    const handle = setTimeout(() => {
      setShown(true)
    }, 400)
    return () => {
      clearTimeout(handle)
    }
  }, [])
  return shown ? <span className="account-working" aria-hidden="true" /> : null
}

/** Usage: figures and meters, and words when there are none. */
function Usage({
  readable,
  usage,
  target,
  onRetry
}: {
  readonly readable: boolean
  readonly usage: UsageView | null
  readonly target: number
  readonly onRetry: () => void
}): ReactNode {
  const heading = usage?.state === 'read' ? usage.period_label : 'Usage'
  let body: ReactNode
  if (!readable || usage?.state === 'not_granted') {
    body = <p className="account-note">This sign-in cannot read usage.</p>
  } else if (usage === null) {
    body = <p className="account-note">Usage has not been read yet.</p>
  } else if (usage.state === 'could_not_read') {
    body = (
      <div className="account-actions">
        <p className="account-note">Usage could not be read.</p>
        <Button style={{ minBlockSize: target }} onClick={onRetry}>
          Try again
        </Button>
      </div>
    )
  } else if (usage.state === 'read') {
    body = usage.lines.map((line) => {
      const fraction = usageFraction(line)
      return (
        <div key={line.label} className="account-usage">
          <span className="account-usage-head">
            <span className="account-usage-label">{line.label}</span>
            <span className="account-usage-figure">{describeUsage(line)}</span>
          </span>
          {fraction === null ? null : (
            <span
              className="account-meter"
              role="meter"
              aria-label={`${line.label}: ${describeUsage(line)}`}
              aria-valuenow={line.used}
              aria-valuemin={0}
              aria-valuemax={line.included ?? undefined}
            >
              <span style={{ inlineSize: `${Math.round(fraction * 100)}%` }} />
            </span>
          )}
        </div>
      )
    })
  } else {
    body = null
  }
  return (
    <>
      <p className="account-section-title">{heading}</p>
      <Card>{body}</Card>
    </>
  )
}
