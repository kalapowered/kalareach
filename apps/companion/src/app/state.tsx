/**
 * What every screen shares: the port, the current place, the passing messages, and this
 * computer's owner confirmations.
 *
 * There is no store framework here. The application's state is small and almost all of it belongs
 * to one screen; the things that do not are the host port, the toast and the confirmations, and a
 * context is the plainest way to hold those.
 */

import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useState,
  useSyncExternalStore,
  type ReactNode
} from 'react'

import type { HostPort } from '../host/port'
import type { ToastAction, ToastMessage } from '../components/ui'
import { SessionStates, type SessionState } from '../model/sessions'
import { ConfirmationStore } from '../pairing/confirmationStore'

/** The screens the navigation model has. */
export type Place =
  | { readonly view: 'attention' }
  | { readonly view: 'sessions' }
  | { readonly view: 'hosts' }
  | { readonly view: 'changesets' }
  | { readonly view: 'plugins' }
  | { readonly view: 'pairing' }
  | { readonly view: 'setup' }
  | { readonly view: 'session'; readonly sessionId: string; readonly pane: 'semantic' | 'terminal' }


interface AppValue {
  readonly port: HostPort
  /** What every session's views share, kept apart from every other session's. */
  readonly sessions: SessionStates
  readonly place: Place
  readonly go: (place: Place) => void
  readonly toast: ToastMessage | null
  /** Shows a passing message, with the one thing it offers to do, if any. */
  readonly say: (
    text: string,
    tone?: 'success' | 'danger' | 'pending',
    action?: ToastAction
  ) => void
  readonly dismissToast: () => void
  /** The open session tabs, in the order the person opened them. */
  readonly tabs: readonly string[]
  readonly openTab: (sessionId: string) => void
  readonly closeTab: (sessionId: string) => void
  /** This computer's owner confirmations, which every screen reads. */
  readonly confirmations: ConfirmationStore
}

const AppContext = createContext<AppValue | null>(null)

/** Provides the port and the place to everything under it. */
export function AppProvider({
  port,
  children,
  initialPlace = { view: 'attention' }
}: {
  readonly port: HostPort
  readonly children: ReactNode
  readonly initialPlace?: Place
}): ReactNode {
  const [place, setPlace] = useState<Place>(initialPlace)
  const [toast, setToast] = useState<ToastMessage | null>(null)
  const [tabs, setTabs] = useState<readonly string[]>([])
  // One store per window, created once. A store built during render would be a different store on
  // every render, and every session's state would go with the old one.
  const [sessions] = useState(() => new SessionStates())

  const say = useCallback(
    (text: string, tone: 'success' | 'danger' | 'pending' = 'success', action?: ToastAction) => {
      setToast({ id: Date.now() + Math.random(), text, tone, action })
    },
    []
  )

  const openTab = useCallback((sessionId: string) => {
    setTabs((current) => (current.includes(sessionId) ? current : [...current, sessionId]))
  }, [])

  const closeTab = useCallback(
    (sessionId: string) => {
      setTabs((current) => current.filter((each) => each !== sessionId))
      sessions.forget(sessionId)
    },
    [sessions]
  )

  const go = useCallback(
    (next: Place) => {
      setPlace(next)
      if (next.view === 'session') openTab(next.sessionId)
    },
    [openTab]
  )

  // One store for the window's life: a request is announced once, on whichever screen the person
  // is, and "Review" takes them to it in Attention.
  const [confirmations] = useState(
    () =>
      new ConfirmationStore(port, (request, review) => {
        say(`${request.host_name} needs your confirmation`, 'pending', {
          label: 'Review',
          act: () => {
            go({ view: 'attention' })
            review()
          }
        })
      })
  )

  const value = useMemo<AppValue>(
    () => ({
      port,
      sessions,
      place,
      go,
      toast,
      say,
      dismissToast: () => {
        setToast(null)
      },
      tabs,
      openTab,
      closeTab,
      confirmations
    }),
    [port, sessions, place, go, toast, say, tabs, openTab, closeTab, confirmations]
  )

  return <AppContext.Provider value={value}>{children}</AppContext.Provider>
}

/** Reads the shared value. */
export function useApp(): AppValue {
  const value = useContext(AppContext)
  if (!value) throw new Error('This component must be rendered inside the application.')
  return value
}

/**
 * Reads and writes one session's state.
 *
 * The update function is bound to this session, so a view cannot write another session's state
 * even by mistake.
 */
export function useSession(sessionId: string): {
  readonly state: SessionState
  readonly update: (change: (current: SessionState) => SessionState) => void
} {
  const { sessions } = useApp()
  const state = useSyncExternalStore(
    useCallback((listener) => sessions.subscribe(listener), [sessions]),
    () => sessions.get(sessionId)
  )
  const update = useCallback(
    (change: (current: SessionState) => SessionState) => {
      sessions.update(sessionId, change)
    },
    [sessions, sessionId]
  )
  return { state, update }
}
