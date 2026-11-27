/**
 * The shell: the navigation model, and whichever screen it is on.
 *
 * Hosts, Sessions and Attention are the navigation. Everything else is reached from one of them,
 * and settings are never a fourth destination: they open over whatever the person is doing.
 */

import {
  useCallback,
  useEffect,
  useMemo,
  useLayoutEffect,
  useRef,
  useState,
  useSyncExternalStore,
  type ReactNode,
  type RefObject
} from 'react'

import type { ActionRight } from '@kalareach/protocol'

import { AccountPanel, useAccount } from './components/AccountPanel'
import { Brand, Button, INERT_SUPPORTED, Sheet, Toast, closeWithSheets, useModalSurface } from './components/ui'
import { isSigningIn, type AccountView } from './model/account'
import { ShellConnection } from './app/rights'
import { useApp, type Place } from './app/state'
import { Attention } from './views/Attention'
import { ChangeSets } from './views/ChangeSets'
import { Devices } from './views/Devices'
import { Hosts, Sessions } from './views/Sessions'
import { Pairing } from './views/Pairing'
import { Plugins } from './views/Plugins'
import { Session } from './views/Session'
import { setupLinkFor, usePlatform } from './setup/platform'
import { Setup } from './setup/Setup'
import { KeptDrafts } from './views/KeptDrafts'
import { useRebind } from './app/drafts'
import { failureMessage, type ConnectionState } from './host/port'
import { useConfirmations } from './pairing/Confirmations'

const NAVIGATION: readonly { readonly place: Place; readonly label: string }[] = [
  { place: { view: 'attention' }, label: 'Attention' },
  { place: { view: 'sessions' }, label: 'Sessions' },
  { place: { view: 'hosts' }, label: 'Hosts' },
  { place: { view: 'devices' }, label: 'Devices' },
  { place: { view: 'changesets' }, label: 'Change sets' },
  { place: { view: 'plugins' }, label: 'Plugins' }
]

/**
 * The windows in which the sidebar does not stand beside the page but opens over it from one control
 * in the top bar. It is the query the style rules of the drawer are written for, in the same words:
 * the window changes form at one width, in the page and in its styles together.
 */
const NARROW = '(max-width: 720px)'

function isNarrow(): boolean {
  return window.matchMedia(NARROW).matches
}

/**
 * Whether the words in `ref` run past their box (one that bounds their height), and whether more of
 * them lie below what is shown. Both are read again when the box changes size, when the words
 * scroll and when `text` changes.
 */
function useClipped(ref: RefObject<HTMLElement | null>, text: string | null): { clipped: boolean; more: boolean } {
  const [state, setState] = useState({ clipped: false, more: false })
  useLayoutEffect(() => {
    const element = ref.current
    if (element === null) return
    const read = (): void => {
      const clipped = element.scrollHeight > element.clientHeight + 1
      const more = clipped && element.scrollTop + element.clientHeight < element.scrollHeight - 1
      setState((was) => (was.clipped === clipped && was.more === more ? was : { clipped, more }))
    }
    read()
    element.addEventListener('scroll', read, { passive: true })
    // Every web view the application runs in has the observer; the unit tests' document has not.
    const observer = typeof ResizeObserver === 'undefined' ? null : new ResizeObserver(read)
    observer?.observe(element)
    return () => {
      element.removeEventListener('scroll', read)
      observer?.disconnect()
    }
  }, [ref, text])
  return state
}

/** The element that had the focus as the window changed form, and the form that the change led to. */
interface HeldAtChange {
  readonly control: Element | null
  readonly narrow: boolean
}

/**
 * Whether the window is narrow now, and again each time it becomes or stops being so. The element
 * that has the focus when the window changes form is kept in `held`, with the form that the change
 * leads to: the change is told before the page is drawn again, while the controls the new form takes
 * away are still there. An engine that draws the new form first has taken the focus off a control
 * that the form hides, and `held` is that one. The record holds a form, not the identity of a
 * change: a later change to that form keeps it while the focus is on the body or on nothing,
 * whichever change made it, and a focus that rests on a control replaces it, for that is where the
 * person is. Two schedules have no case: a record that is never told of, which stays until a change
 * to its form finds the focus on the body, and the record then moves the focus; and a render that
 * comes before the telling, where the layout effect that reads the record does not ask where the
 * focus is.
 */
function useNarrow(held: { current: HeldAtChange | null }): boolean {
  const subscribe = useCallback(
    (notify: () => void): (() => void) => {
      const query = window.matchMedia(NARROW)
      let form = query.matches
      // An engine may draw the new form before it tells of the change, and by then it has taken the
      // focus off a control that the new form hides and given it to no other: that control is the
      // one that held it. A focus that went to another control was moved, not lost, and is not kept.
      // A focus that left for no control does not say why: a press on a part that takes no focus, or a
      // window that lost the focus, leaves it the same way, and is kept the same way.
      const blurred = (event: FocusEvent): void => {
        if (query.matches !== form && event.relatedTarget === null && event.target instanceof Element) {
          held.current = { control: event.target, narrow: query.matches }
        }
      }
      const changed = (): void => {
        form = query.matches
        const active = document.activeElement
        const lost = active === null || active === document.body
        const kept = held.current
        held.current = kept !== null && kept.narrow === form && lost ? kept : { control: active, narrow: form }
        notify()
      }
      document.addEventListener('focusout', blurred, true)
      query.addEventListener('change', changed)
      return () => {
        document.removeEventListener('focusout', blurred, true)
        query.removeEventListener('change', changed)
      }
    },
    [held]
  )
  return useSyncExternalStore(subscribe, isNarrow, () => false)
}

/**
 * What the toast says when the host withdrew the connection and the application replaced it. A
 * request refused on the old connection was answered with a failure just before, and a request in
 * flight when the host withdrew it has an outcome nobody knows, so the person is told to check and
 * nothing is sent a second time for them.
 */
const CONNECTION_REPLACED =
  'The connection to this computer was replaced. Check anything that just failed.'

/** The application. */
export function App(): ReactNode {
  const { place, go, toast, dismissToast, port, say, rememberRights } = useApp()
  const confirmations = useConfirmations()
  const waiting = confirmations?.requests.length ?? 0
  // Where the connection stands, as its first answer or a change since said it: null until then,
  // so the bar claims neither contact nor its loss before anything has answered.
  const [connection, setConnection] = useState<{
    readonly connected: boolean
    readonly reason: string | null
    readonly rights: readonly ActionRight[] | null
    readonly paired: boolean
  } | null>(null)
  // The connection's latest state whole, which the inbox draws its row of contact from.
  const [latest, setLatest] = useState<ConnectionState | null>(null)
  const account = useAccount(port)
  // What the setup link is called depends on the platform, which only the host's own reading says.
  const platform = usePlatform(port)
  const [accountOpen, setAccountOpen] = useState(false)
  // Drafts the application was started or disconnected with are bound to their conversations again
  // once the host says where those stand.
  useRebind(connection?.connected === true)

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

  // How many replacements the last state counted: none until a state has been taken in, so the
  // count the page starts with is not a replacement it saw.
  const replacements = useRef<number | null>(null)

  // The port's feed gives the latest state once it has one and then each change, once and in order.
  useEffect(
    () =>
      port.watchConnection(
        (state) => {
          if (replacements.current !== null && state.replaced > replacements.current) {
            say(CONNECTION_REPLACED, 'pending')
          }
          replacements.current = Math.max(replacements.current ?? 0, state.replaced)
          setLatest(state)
          if (state.connected && state.rights !== null) rememberRights(state.rights)
          setConnection({
            connected: state.connected,
            reason: state.reason,
            rights: state.connected ? state.rights : null,
            paired: state.connected && state.paired
          })
        },
        // A failure to answer is itself an answer: the window says it is not connected, and why.
        (failure) => {
          setConnection({
            connected: false,
            reason: failureMessage(failure),
            rights: null,
            paired: false
          })
        }
      ),
    [port, rememberRights, say]
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

  const held = useMemo(
    () => ({ rights: connection?.rights ?? null, paired: connection?.paired ?? false }),
    [connection]
  )

  // Below the sidebar's width it is a drawer, which one control in the top bar opens. While it is
  // open the page behind takes no focus and no scroll, and the drawer closes by Escape, by a press
  // outside it, by its own control or by a choice. Where the focus goes then is decided by how it
  // closed: back to the control that opened it, or onto the page that was chosen.
  const words = useRef<HTMLSpanElement | null>(null)
  const { clipped, more } = useClipped(words, connection === null ? null : connection.connected ? 'connected' : (connection.reason ?? ''))
  const heldAtChange = useRef<HeldAtChange | null>(null)
  const narrow = useNarrow(heldAtChange)
  const [wasNarrow, setWasNarrow] = useState(narrow)
  const [navigationOpen, setNavigationOpen] = useState(false)
  // Motion answers a person's own act. The drawer goes out by a transition only once a person has
  // opened it in this form; a window that changes form puts the sidebar in its place without one.
  // Where the web view has no `inert`, the closed drawer is out of reach only by being hidden, and
  // a drawer that is still going out is not: there it leaves at once, with no exit.
  const [navigationUsed, setNavigationUsed] = useState(false)
  // A window widened past the drawer's width while it was open leaves the sidebar where it stands,
  // and one narrowed again meets the drawer closed, and not yet used.
  if (wasNarrow !== narrow) {
    setWasNarrow(narrow)
    if (!narrow) {
      setNavigationOpen(false)
      setNavigationUsed(false)
    }
  }
  const open = narrow && navigationOpen
  const sidebar = useRef<HTMLElement | null>(null)
  const workspace = useRef<HTMLDivElement | null>(null)
  const skipLink = useRef<HTMLAnchorElement | null>(null)
  const menu = useRef<HTMLButtonElement | null>(null)
  const page = useRef<HTMLElement | null>(null)
  const focusAfter = useRef<HTMLElement | null>(null)
  const openNavigation = useCallback(() => {
    focusAfter.current = menu.current
    setNavigationOpen(true)
    setNavigationUsed(true)
  }, [])
  const closeNavigation = useCallback((returnTo: 'menu' | 'page') => {
    focusAfter.current = returnTo === 'menu' ? menu.current : page.current
    setNavigationOpen(false)
  }, [])
  const closeToMenu = useCallback(() => {
    closeNavigation('menu')
  }, [closeNavigation])
  // The destination that is shown has the focus as the drawer opens, so a person sees where they are.
  const firstStop = useCallback(
    () =>
      sidebar.current?.querySelector<HTMLElement>('[aria-current="page"]') ??
      sidebar.current?.querySelector<HTMLElement>('.nav-item') ??
      null,
    []
  )
  // A window that changes form takes some controls away. Narrowed, the sidebar becomes the closed
  // drawer, and a control of it that had the focus hands it to "Menu", the control that now stands for
  // the sidebar; the drawer does not open, for a resize is not an act that it answers. Widened,
  // "Menu" and "Close menu" go, and when one of them had the focus it goes to the item of the
  // destination that is shown, where the sidebar now stands.
  useLayoutEffect(() => {
    const record = heldAtChange.current
    heldAtChange.current = null
    const held = record !== null && record.narrow === narrow ? record.control : null
    if (!(held instanceof HTMLElement)) return
    if (narrow) {
      if (sidebar.current?.contains(held) === true) menu.current?.focus()
      return
    }
    if (!held.hasAttribute('data-menu-control')) return
    const item = firstStop()
    focusAfter.current = item
    item?.focus()
  }, [narrow, firstStop])
  // Where the focus goes as Account closes when the control that led there is gone: to "Menu" in the
  // window's narrow form, and in the wide one, which has no "Menu", to the shown destination's item.
  const whenMenuIsGone = useCallback(() => menu.current ?? firstStop(), [firstStop])
  useModalSurface(sidebar, open, closeToMenu, {
    firstStop,
    returnTo: focusAfter,
    inactive: [workspace, skipLink],
    still: true
  })
  // An action that takes the person to another view closes what is over the page, as it closes the
  // sheets, and the page is where the focus goes.
  useEffect(() => {
    if (!open) return
    return closeWithSheets(() => {
      closeNavigation('page')
    })
  }, [open, closeNavigation])
  // A choice in the drawer closes it and leaves the focus on the page that was chosen.
  const chose = (): void => {
    if (narrow) closeNavigation('page')
  }

  const shell = (
    <div className="app-shell">
      <a className="skip-link" href="#main" ref={skipLink}>
        Skip to content
      </a>
      <aside
        id="workspace-navigation"
        className="sidebar"
        aria-label="Workspace navigation"
        ref={sidebar}
        data-open={narrow ? String(open) : undefined}
        data-used={narrow ? String(navigationUsed && INERT_SUPPORTED) : undefined}
        inert={narrow && !open}
      >
        {narrow ? (
          <div className="drawer-head">
            <Button data-menu-control="close" onClick={closeToMenu}>
              Close menu
            </Button>
            <Brand />
          </div>
        ) : (
          <Brand />
        )}
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
                chose()
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
              chose()
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
              chose()
            }}
          >
            {setupLinkFor(platform)}
          </button>
          <button
            type="button"
            className="nav-item nav-item-account"
            aria-haspopup="dialog"
            onClick={() => {
              setAccountOpen(true)
              // The sheet that opens is the Account sheet's: the focus waits on the control that
              // led here, which is where closing Account returns it.
              if (narrow) closeNavigation('menu')
            }}
          >
            <span className="nav-item-lines">
              <span>Account</span>
              <AccountDetail view={account.view} />
            </span>
          </button>
        </div>
      </aside>
      {narrow ? (
        <div
          className="scrim drawer-scrim"
          data-open={String(open)}
          data-testid="drawer-scrim"
          role="presentation"
          onClick={closeToMenu}
        />
      ) : null}

      <div className="workspace" ref={workspace}>
        <header className="topbar">
          <span className="row">
            {narrow ? (
              <Button
                ref={menu}
                data-menu-control="open"
                aria-expanded={open}
                aria-controls="workspace-navigation"
                onClick={openNavigation}
              >
                Menu
              </Button>
            ) : null}
            <span
              className="connection"
              ref={words}
              data-more={clipped ? String(more) : undefined}
              {...(clipped ? { tabIndex: 0, role: 'group', 'aria-label': 'Connection status' } : {})}
            >
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

        <main id="main" tabIndex={-1} ref={page}>
          {place.view === 'attention' ? <Attention latest={latest} /> : null}
          {place.view === 'sessions' ? <Sessions /> : null}
          {place.view === 'hosts' ? <Hosts /> : null}
          {place.view === 'devices' ? <Devices /> : null}
          {place.view === 'changesets' ? <ChangeSets /> : null}
          {place.view === 'plugins' ? <Plugins /> : null}
          {place.view === 'pairing' ? <Pairing /> : null}
          {place.view === 'setup' ? <Setup /> : null}
          {place.view === 'drafts' ? (
            <KeptDrafts
              onBack={() => {
                go({ view: 'sessions' })
              }}
            />
          ) : null}
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
        closeLabel="Close the account panel"
        focusWhenGone={whenMenuIsGone}
        onClose={() => {
          setAccountOpen(false)
        }}
      >
        <AccountPanel account={account} port={port} surface="desktop" />
      </Sheet>

      <Toast message={toast} onDismiss={dismissToast} />
    </div>
  )
  return <ShellConnection.Provider value={held}>{shell}</ShellConnection.Provider>
}

/** The Account item's second line: signing in, or who is signed in. */
function AccountDetail({ view }: { readonly view: AccountView | null }): ReactNode {
  if (view && isSigningIn(view)) return <span className="nav-item-detail">Signing in…</span>
  if (view?.state === 'signed_in' && view.email !== null) {
    return <span className="nav-item-detail">{view.email}</span>
  }
  return null
}
