/**
 * The shell: the navigation model, and whichever screen it is on.
 *
 * Hosts, Sessions and Attention are the navigation. Everything else is reached from one of them,
 * and settings are never a fourth destination: they open over whatever the person is doing.
 */

import { useEffect, useRef, useState, type ReactNode } from 'react'

import { AccountPanel, useAccount } from './components/AccountPanel'
import { Brand, Sheet, Toast } from './components/ui'
import { isSigningIn, type AccountView } from './model/account'
import { useApp, type Place } from './app/state'
import { Attention } from './views/Attention'
import { ChangeSets } from './views/ChangeSets'
import { Hosts, Sessions } from './views/Sessions'
import { Pairing } from './views/Pairing'
import { Plugins } from './views/Plugins'
import { Session } from './views/Session'
import { Setup } from './setup/Setup'
import { failureMessage, follow } from './host/port'
import { useConfirmations } from './pairing/Confirmations'

const NAVIGATION: readonly { readonly place: Place; readonly label: string }[] = [
  { place: { view: 'attention' }, label: 'Attention' },
  { place: { view: 'sessions' }, label: 'Sessions' },
  { place: { view: 'hosts' }, label: 'Hosts' },
  { place: { view: 'changesets' }, label: 'Change sets' },
  { place: { view: 'plugins' }, label: 'Plugins' }
]

/** The application. */
export function App(): ReactNode {
  const { place, go, toast, dismissToast, port, say } = useApp()
  const confirmations = useConfirmations()
  const waiting = confirmations?.requests.length ?? 0
  // Where the connection stands, as its first answer or a change since said it: null until then,
  // so the bar claims neither contact nor its loss before anything has answered.
  const [connection, setConnection] = useState<{
    readonly connected: boolean
    readonly reason: string | null
  } | null>(null)
  const account = useAccount(port)
  const [accountOpen, setAccountOpen] = useState(false)

  // A sign-in carries on while the sheet is closed. When it finishes then, the toast says so.
  const lastAccount = useRef<AccountView | null>(null)
  useEffect(() => {
    const before = lastAccount.current
    lastAccount.current = account.view
    if (accountOpen || !before || !isSigningIn(before)) return
    if (account.view?.state === 'signed_in') {
      say(account.view.email === null ? 'Signed in.' : `Signed in as ${account.view.email}.`)
    }
  }, [account.view, accountOpen, say])

  // The state is read once the listener is registered, so no change can fall between the two, and
  // a change heard before the read answers is at least as new as it.
  useEffect(
    () =>
      follow(
        (listener) => port.onConnection(listener),
        () => port.connectionState(),
        (state) => {
          setConnection({ connected: state.connected, reason: state.reason })
        },
        // A failure to answer is itself an answer: the window says it is not connected, and why.
        (failure) => {
          setConnection({ connected: false, reason: failureMessage(failure) })
        }
      ),
    [port]
  )

  // The last input device decides whether anything animates. A keyboard-driven change is instant;
  // a pointer-driven one gets its transition back.
  useEffect(() => {
    const keyboard = () => {
      document.documentElement.dataset.input = 'keyboard'
    }
    const pointer = () => {
      document.documentElement.dataset.input = 'pointer'
    }
    window.addEventListener('keydown', keyboard, true)
    window.addEventListener('pointerdown', pointer, true)
    return () => {
      window.removeEventListener('keydown', keyboard, true)
      window.removeEventListener('pointerdown', pointer, true)
    }
  }, [])

  return (
    <div className="app-shell">
      <a className="skip-link" href="#main">
        Skip to content
      </a>
      <aside className="sidebar" aria-label="Workspace navigation">
        <Brand />
        <nav className="nav-group">
          <p className="eyebrow">Workspace</p>
          {NAVIGATION.map((item) => (
            <button
              key={item.label}
              type="button"
              className="nav-item"
              aria-current={item.place.view === place.view ? 'page' : undefined}
              onClick={() => {
                go(item.place)
              }}
            >
              {item.label}
              {item.place.view === 'attention' && waiting > 0 ? (
                <span className="count" aria-label={`${waiting} waiting for confirmation`}>
                  {waiting}
                </span>
              ) : null}
            </button>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <button
            type="button"
            className="nav-item"
            aria-current={place.view === 'pairing' ? 'page' : undefined}
            onClick={() => {
              go({ view: 'pairing' })
            }}
          >
            Pair with a host
          </button>
          <button
            type="button"
            className="nav-item"
            aria-current={place.view === 'setup' ? 'page' : undefined}
            onClick={() => {
              go({ view: 'setup' })
            }}
          >
            Set up this Mac
          </button>
          <button
            type="button"
            className="nav-item nav-item-account"
            aria-haspopup="dialog"
            onClick={() => {
              setAccountOpen(true)
            }}
          >
            <span className="nav-item-lines">
              <span>Account</span>
              <AccountDetail view={account.view} />
            </span>
          </button>
        </div>
      </aside>

      <div className="workspace">
        <header className="topbar">
          <span className="row">
            <span className="connection">
              {connection === null ? (
                'Checking the connection…'
              ) : (
                <>
                  <span className={`status-dot${connection.connected ? '' : ' offline'}`} />
                  {connection.connected
                    ? 'Connected to this machine'
                    : (connection.reason ?? 'Not in contact')}
                </>
              )}
            </span>
          </span>
        </header>

        <main id="main" tabIndex={-1}>
          {place.view === 'attention' ? <Attention /> : null}
          {place.view === 'sessions' ? <Sessions /> : null}
          {place.view === 'hosts' ? <Hosts /> : null}
          {place.view === 'changesets' ? <ChangeSets /> : null}
          {place.view === 'plugins' ? <Plugins /> : null}
          {place.view === 'pairing' ? <Pairing /> : null}
          {place.view === 'setup' ? <Setup /> : null}
          {place.view === 'session' ? (
            <Session sessionId={place.sessionId} pane={place.pane} />
          ) : null}
        </main>

        <footer className="statusbar">
          <span>
            <span className="status-dot" /> Sessions stay on your hosts
          </span>
        </footer>
      </div>

      <Sheet
        open={accountOpen}
        title="Account"
        description="Sessions keep running while this is open."
        onClose={() => {
          setAccountOpen(false)
        }}
      >
        <AccountPanel account={account} surface="desktop" />
      </Sheet>

      <Toast message={toast} onDismiss={dismissToast} />
    </div>
  )
}

/** The Account item's second line: signing in, or who is signed in. */
function AccountDetail({ view }: { readonly view: AccountView | null }): ReactNode {
  if (view && isSigningIn(view)) return <span className="nav-item-detail">Signing in…</span>
  if (view?.state === 'signed_in' && view.email !== null) {
    return <span className="nav-item-detail">{view.email}</span>
  }
  return null
}
