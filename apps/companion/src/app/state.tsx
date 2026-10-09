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

import type { ActionRight } from '@kalareach/protocol'

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
  | {
      readonly view: 'session'
      readonly sessionId: string
      readonly pane: 'semantic' | 'terminal' | 'output'
    }


interface AppValue {
  readonly port: HostPort
  /** What every session's views share, kept apart from every other session's. */
  readonly sessions: SessionStates
  /**
   * The rights the connection last reported, kept while contact is out and for a screen that opens
   * after it ended. The shell writes it as it hears the connection; a control that only keeps what
   * a person typed reads it.
   */
  readonly lastRights: readonly ActionRight[] | null
  /** Notes the rights the connection has just reported. */
  readonly rememberRights: (rights: readonly ActionRight[]) => void
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
  /**
   * How many times the answers kept on this device have changed since the window opened. A list of
   * them reads again when it moves, so an answer given on one screen is listed on another at once.
   */
  readonly keptVersion: number
  /** Says the answers kept on this device changed. */
  readonly keptChanged: () => void
}

const AppContext = createContext<AppValue | null>(null)

/** The topic of the messages that announce owner confirmations. */
const CONFIRMATIONS_TOPIC = 'owner-confirmations'

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
  const [keptVersion, setKeptVersion] = useState(0)
  const keptChanged = useCallback(() => {
    setKeptVersion((current) => current + 1)
  }, [])
  // One store per window, created once. A store built during render would be a different store on
  // every render, and every session's state would go with the old one.
  const [sessions] = useState(() => new SessionStates())
  const [lastRights, setLastRights] = useState<readonly ActionRight[] | null>(null)
  const rememberRights = useCallback((rights: readonly ActionRight[]) => {
    setLastRights((held) =>
      held !== null && held.length === rights.length && held.every((each, i) => each === rights[i])
        ? held
        : rights
    )
  }, [])

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

  // One store for the window's life: requests are announced once, on whichever screen the person
  // is, and "Review" takes them to the first of them in Attention. A message that is already
  // announcing requests takes in the ones that arrive after it, in place, so what the person is
  // using in it stays where it is.
  const [confirmations] = useState(
    () =>
      new ConfirmationStore(port, (arrived, waiting, review) => {
        const [first] = arrived
        const text =
          waiting === 1 && first !== undefined
            ? `${first.host_name} needs your confirmation`
            : `${waiting} requests need your confirmation`
        const action: ToastAction = {
          label: 'Review',
          act: () => {
            go({ view: 'attention' })
            review()
          }
        }
        setToast((current) =>
          current?.topic === CONFIRMATIONS_TOPIC
            ? { ...current, text, action, said: (current.said ?? 0) + 1 }
            : { id: Date.now() + Math.random(), text, tone: 'pending', action, topic: CONFIRMATIONS_TOPIC }
        )
      })
  )

  const value = useMemo<AppValue>(
    () => ({
      port,
      sessions,
      lastRights,
      rememberRights,
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
      confirmations,
      keptVersion,
      keptChanged
    }),
    [
      port,
      sessions,
      lastRights,
      rememberRights,
      place,
      go,
      toast,
      say,
      tabs,
      openTab,
      closeTab,
      confirmations,
      keptVersion,
      keptChanged
    ]
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
