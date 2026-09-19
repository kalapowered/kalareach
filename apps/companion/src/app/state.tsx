/**
 * What every screen shares: the port, the current place, and the passing messages.
 *
 * There is no store framework here. The application's state is small and almost all of it belongs
 * to one screen; the two things that do not are the host port and the toast, and a context is the
 * plainest way to hold those.
 */

import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useState,
  type ReactNode
} from 'react'

import type { HostPort } from '../host/port'
import type { ToastMessage } from '../components/ui'

/** The screens the navigation model has. */
export type Place =
  | { readonly view: 'attention' }
  | { readonly view: 'sessions' }
  | { readonly view: 'hosts' }
  | { readonly view: 'changesets' }
  | { readonly view: 'plugins' }
  | { readonly view: 'pairing' }
  | { readonly view: 'session'; readonly sessionId: string; readonly pane: 'semantic' | 'terminal' }

/** The environment the desktop application is looking at. */
export const ENVIRONMENT_ID = '3f1a2c40-11aa-4b2c-9d3e-000000000001'

interface AppValue {
  readonly port: HostPort
  readonly place: Place
  readonly go: (place: Place) => void
  readonly toast: ToastMessage | null
  readonly say: (text: string, tone?: 'success' | 'danger') => void
  readonly dismissToast: () => void
  /** The open session tabs, in the order the person opened them. */
  readonly tabs: readonly string[]
  readonly openTab: (sessionId: string) => void
  readonly closeTab: (sessionId: string) => void
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

  const say = useCallback((text: string, tone: 'success' | 'danger' = 'success') => {
    setToast({ id: Date.now() + Math.random(), text, tone })
  }, [])

  const openTab = useCallback((sessionId: string) => {
    setTabs((current) => (current.includes(sessionId) ? current : [...current, sessionId]))
  }, [])

  const closeTab = useCallback((sessionId: string) => {
    setTabs((current) => current.filter((each) => each !== sessionId))
  }, [])

  const go = useCallback(
    (next: Place) => {
      setPlace(next)
      if (next.view === 'session') openTab(next.sessionId)
    },
    [openTab]
  )

  const value = useMemo<AppValue>(
    () => ({
      port,
      place,
      go,
      toast,
      say,
      dismissToast: () => {
        setToast(null)
      },
      tabs,
      openTab,
      closeTab
    }),
    [port, place, go, toast, say, tabs, openTab, closeTab]
  )

  return <AppContext.Provider value={value}>{children}</AppContext.Provider>
}

/** Reads the shared value. */
export function useApp(): AppValue {
  const value = useContext(AppContext)
  if (!value) throw new Error('This component must be rendered inside the application.')
  return value
}
