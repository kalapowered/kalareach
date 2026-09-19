/**
 * The phone's shell.
 *
 * Four destinations along the bottom, one screen at a time, and settings over whatever is showing.
 * Navigation is used dozens of times a day, so nothing about it animates: a transition between
 * tabs is a delay between a person deciding and the interface agreeing.
 *
 * The shell owns the connection state and the lifecycle, because both are facts about the device
 * rather than about a screen, and both are what the recovery banner and the inbox are drawn from.
 */

import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react'

import { useApp } from '../app/state'
import { Toast } from '../components/ui'
import { failureMessage } from '../host/port'
import {
  AccountGlyph,
  AttentionGlyph,
  HostsGlyph,
  SessionsGlyph,
  TabBar,
  TopBar,
  type Destination
} from './components/chrome'
import { Account } from './views/Account'
import { Inbox } from './views/Inbox'
import { MobileHosts, MobileSessions } from './views/Places'
import { MobileSession } from './views/MobileSession'
import type { Channel, AccountState, Usage } from './model/account'
import { useKeyboardInset, useLifecycle } from './useLifecycle'
import { detectSurface, type Surface } from './platform'
import './mobile.css'

/** The four destinations. */
type Tab = 'attention' | 'sessions' | 'hosts' | 'account'

/** Where the shell is: a destination, and the session open inside it when there is one. */
interface Place {
  readonly tab: Tab
  readonly sessionId?: string
}

/** What this build is, which decides only what the account screen may show. */
export interface MobileBuild {
  readonly channel: Channel
  readonly account: AccountState
  readonly usage: Usage | null
}

const DEFAULT_BUILD: MobileBuild = {
  channel: 'app_store',
  account: { kind: 'local_only' },
  usage: null
}

/** The phone application. */
export function MobileApp({
  surface,
  build = DEFAULT_BUILD,
  storage
}: {
  readonly surface?: Surface
  readonly build?: MobileBuild
  readonly storage?: Storage | null
}): ReactNode {
  const { port, toast, dismissToast } = useApp()
  const resolved =
    surface ??
    detectSurface(
      typeof navigator === 'undefined' ? '' : navigator.userAgent,
      typeof navigator === 'undefined' ? 0 : navigator.maxTouchPoints
    )
  const [place, setPlace] = useState<Place>({ tab: 'attention' })
  const [connection, setConnection] = useState<{ connected: boolean; reason: string | null }>({
    connected: false,
    reason: null
  })
  const [actionable, setActionable] = useState(0)
  const lifecycle = useLifecycle(storage)
  useKeyboardInset()

  useEffect(() => {
    document.documentElement.dataset.surface = resolved
    return () => {
      delete document.documentElement.dataset.surface
    }
  }, [resolved])

  useEffect(() => {
    let watching = true
    const read = () => {
      port
        .connectionState()
        .then((state) => {
          if (!watching) return
          setConnection({ connected: state.connected, reason: state.reason })
        })
        .catch((failure: unknown) => {
          if (!watching) return
          setConnection({ connected: false, reason: failureMessage(failure) })
        })
    }
    read()
    const stop = port.subscribe((event) => {
      const body = event.body as { kind?: string }
      if (body.kind === 'connection') read()
    })
    return () => {
      watching = false
      stop()
    }
  }, [port])

  const destinations = useMemo<readonly Destination[]>(
    () => [
      { id: 'attention', label: 'Attention', glyph: <AttentionGlyph />, badge: actionable },
      { id: 'sessions', label: 'Sessions', glyph: <SessionsGlyph /> },
      { id: 'hosts', label: 'Hosts', glyph: <HostsGlyph /> },
      { id: 'account', label: 'Account', glyph: <AccountGlyph /> }
    ],
    [actionable]
  )

  const openSession = useCallback((sessionId: string) => {
    setPlace({ tab: 'sessions', sessionId })
  }, [])

  const inSession = place.tab === 'sessions' && place.sessionId !== undefined
  const title = inSession
    ? 'Session'
    : place.tab === 'attention'
      ? 'Attention'
      : place.tab === 'sessions'
        ? 'Sessions'
        : place.tab === 'hosts'
          ? 'Hosts'
          : 'Account'

  // Android's system back leaves a session the same way the bar's control does, so the two are one
  // behaviour rather than two.
  useEffect(() => {
    if (!inSession) return
    const onPop = () => {
      setPlace({ tab: 'sessions' })
    }
    window.history.pushState({ kr: 'session' }, '')
    window.addEventListener('popstate', onPop)
    return () => {
      window.removeEventListener('popstate', onPop)
    }
  }, [inSession])

  return (
    <div className="m-shell" data-surface={resolved}>
      <TopBar
        title={title}
        surface={resolved}
        connection={connection}
        onBack={
          inSession
            ? () => {
                setPlace({ tab: 'sessions' })
              }
            : undefined
        }
        backLabel="Back to sessions"
      />

      <main className="m-main" id="main" tabIndex={-1}>
        {place.tab === 'attention' ? (
          <Inbox surface={resolved} onOpenSession={openSession} onCounts={setActionable} />
        ) : null}
        {place.tab === 'sessions' && !inSession ? (
          <MobileSessions surface={resolved} onOpen={openSession} />
        ) : null}
        {inSession && place.sessionId ? (
          <MobileSession
            sessionId={place.sessionId}
            surface={resolved}
            lifecycle={lifecycle}
            connected={connection.connected}
          />
        ) : null}
        {place.tab === 'hosts' ? <MobileHosts surface={resolved} /> : null}
        {place.tab === 'account' ? (
          <Account
            surface={resolved}
            channel={build.channel}
            account={build.account}
            usage={build.usage}
          />
        ) : null}
      </main>

      <TabBar
        destinations={destinations}
        current={place.tab}
        surface={resolved}
        onChoose={(id) => {
          setPlace({ tab: id as Tab })
        }}
      />

      <Toast message={toast} onDismiss={dismissToast} />
    </div>
  )
}
