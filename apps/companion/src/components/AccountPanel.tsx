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
 * makes it instant. There is no spinner: while the browser is open the application is waiting for
 * the person rather than working, and the exchange after it is short and says "Signing in…" with
 * the status marked busy. Every motion in the interface lasts 120 to 200 ms, which leaves no room
 * for a looping one.
 *
 * Nothing to buy: no plan, no price, no balance, no link and no form. Usage is figures and meters.
 *
 * A signed-in account can be deleted from the foot of the panel. The step replaces the cards while
 * it is open and the cards stay mounted under a hidden wrapper, so cancelling leaves the panel as it
 * was and `SyncPanel` reads nothing again.
 */

import { useCallback, useEffect, useId, useRef, useState, type ReactNode } from 'react'

import { follow, type HostPort } from '../host/port'
import { minimumTarget, type Surface } from '../mobile/platform'
import {
  SIGN_IN_HELP,
  describeAccount,
  describeOutcome,
  describeUnavailable,
  describeUsage,
  usageFraction,
  type AccountView,
  type ServiceLine,
  type UsageView
} from '../model/account'
import { ENTRY_NOTE } from '../model/deletion'
import { DeleteAccount, useDeletion } from './DeleteAccount'
import { SyncPanel } from './SyncPanel'
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

/** The grant a view says is signed in, or null when none is. */
function generationOf(view: AccountView | null): string | null {
  return view?.state === 'signed_in' ? view.generation : null
}

/**
 * Reads where the device stands and follows every change the backend publishes.
 *
 * Usage belongs to one grant, which the backend names in the view and in each usage it reads. A
 * usage answer is kept only when the grant it was read with is still the one the view shows, so
 * figures read for one sign-in are never shown for another, however late they arrive, including
 * a sign-in another window wrote into the shared store.
 */
export function useAccount(port: HostPort): AccountHandle {
  const [view, setView] = useState<AccountView | null>(null)
  const [usage, setUsage] = useState<{
    readonly generation: string
    readonly usage: UsageView
  } | null>(null)
  const current = useRef<string | null>(null)

  const show = useCallback((next: AccountView) => {
    current.current = generationOf(next)
    setView(next)
  }, [])

  // Where the device stands is read once the listener is registered, so no change falls between
  // the two, and a change heard before the read answers is the newer one.
  useEffect(
    () =>
      follow(
        (listener) => port.onAccount(listener),
        () => port.accountStatus(),
        show,
        () => {
          show({ state: 'signed_out', outcome: null })
        }
      ),
    [port, show]
  )

  const readUsage = useCallback(() => {
    const asked = current.current
    if (asked === null) return
    const keep = (read: UsageView) => {
      if (asked !== current.current) return
      if (read.state === 'read' && read.generation !== asked) return
      setUsage({ generation: asked, usage: read })
    }
    port
      .accountUsage()
      .then(keep)
      .catch(() => {
        keep({ state: 'could_not_read' })
      })
  }, [port])

  const generation = generationOf(view)
  const readable = view?.state === 'signed_in' && view.usage_readable
  useEffect(() => {
    if (readable) readUsage()
  }, [readable, generation, readUsage])

  const signIn = useCallback(() => {
    // The panel says the browser is open before the browser appears, so a return by any path lands
    // on a screen that says what happens next.
    show({ state: 'browser_open' })
    port
      .accountSignIn()
      .then(show)
      .catch(() => {
        show({ state: 'signed_out', outcome: 'browser_failed' })
      })
  }, [port, show])

  const cancel = useCallback(() => {
    void port.accountSignInCancel().catch(() => undefined)
  }, [port])

  const signOut = useCallback(() => {
    port
      .accountSignOut()
      .then(show)
      .catch(() => {
        show({ state: 'signed_out', outcome: 'sign_out_failed' })
      })
  }, [port, show])

  // Usage is shown only while the sign-in may read it, and only what was read for this grant.
  const shown =
    readable && usage !== null && usage.generation === generation ? usage.usage : null
  return { view, usage: shown, signIn, cancel, signOut, readUsage }
}

/** The account panel. */
export function AccountPanel({
  account,
  port,
  surface
}: {
  readonly account: AccountHandle
  readonly port: HostPort
  readonly surface: Surface
}): ReactNode {
  const { view, usage } = account
  const target = minimumTarget(surface)
  const helpId = useId()
  const statusRef = useRef<HTMLDivElement | null>(null)
  const cancelRef = useRef<HTMLButtonElement | null>(null)
  const previous = useRef<AccountView['state'] | null>(null)
  const deletion = useDeletion(port, view)
  const entryRef = useRef<HTMLButtonElement | null>(null)
  const wasOpen = useRef(false)

  // Leaving the deletion puts focus back where it began: on the button that opened it, or, when the
  // account is gone and the button with it, on the status line of the panel that is left.
  useEffect(() => {
    if (wasOpen.current && !deletion.open) {
      const place = entryRef.current ?? statusRef.current
      place?.focus()
    }
    wasOpen.current = deletion.open
  }, [deletion.open])

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

  const outcome = view.state === 'signed_out' || view.state === 'signed_in' ? view.outcome : null
  const offersSignIn = view.state === 'signed_out' || view.state === 'ended'

  return (
    <div className="account-panel" data-testid="account-panel">
      <div className="account-panel-body" hidden={deletion.open}>
        <Card>
          <div className="account-state" key={view.state}>
            <div
              className="account-status"
              role="status"
              tabIndex={-1}
              ref={statusRef}
              aria-busy={view.state === 'finishing'}
            >
              <p className="account-lead">{describeAccount(view)}</p>
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

        <SyncPanel
          port={port}
          account={view}
          surface={surface}
          closing={deletion.step.name === 'result'}
        />

        <Services port={port} standing={view.state} />

        <p className="account-section-title">Working without an account</p>
        <Card>
          <p className="account-note">
            Your hosts run on your machines. Sessions, agents and terminals work the same whether this
            device is signed in or not, and nothing here needs an account to reach a host you paired.
          </p>
        </Card>

        {view.state === 'signed_in' ? (
          <>
            <p className="account-section-title">Delete account</p>
            <Card>
              <div className="account-actions">
                <p className="account-note">{ENTRY_NOTE}</p>
                <Button
                  ref={entryRef}
                  data-testid="delete-account-open"
                  style={{ minBlockSize: target }}
                  onClick={deletion.begin}
                >
                  Delete account
                </Button>
              </div>
            </Card>
          </>
        ) : null}
      </div>

      {deletion.open ? <DeleteAccount flow={deletion} surface={surface} /> : null}
    </div>
  )
}

/** A service's name as a heading: the library's lower-case words, with a capital to start. */
function serviceTitle(line: ServiceLine): string {
  return line.service.charAt(0).toUpperCase() + line.service.slice(1)
}

/**
 * Which managed services this application holds a client of, and what a person does instead of
 * each it does not. It explains availability and nothing more: no control here waits on it, no
 * service is asked, and a read that fails leaves the section out rather than saying a service is
 * missing. It is read again when the account's standing changes, since signing in and out moves
 * what the application holds.
 */
function Services({
  port,
  standing
}: {
  readonly port: HostPort
  readonly standing: AccountView['state']
}): ReactNode {
  const [lines, setLines] = useState<readonly ServiceLine[] | null>(null)

  useEffect(() => {
    let current = true
    port.accountServices().then(
      (read) => {
        if (current) setLines(read)
      },
      () => {
        if (current) setLines(null)
      }
    )
    return () => {
      current = false
    }
  }, [port, standing])

  if (lines === null || lines.length === 0) return null
  return (
    <>
      <p className="account-section-title">Managed services on this device</p>
      <Card>
        <ul className="account-services" data-testid="account-services">
          {lines.map((line) => (
            <li key={line.service}>
              <span className="account-service-name">{serviceTitle(line)}</span>
              <span className="account-note">{line.explanation}</span>
            </li>
          ))}
        </ul>
        <p className="account-help">
          These are the services this app uses. A host keeps its own relay leases, so none is
          listed here.
        </p>
      </Card>
    </>
  )
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
