/**
 * The phone's shell.
 *
 * Four destinations along the bottom, one screen at a time, and settings over a session, so a person
 * who changes how the application looks has not left it. Navigation is used dozens of times a day,
 * so nothing about it animates: a transition between tabs is a delay between a person deciding and
 * the interface agreeing.
 *
 * The shell owns the connection state and the lifecycle, because both are facts about the device
 * rather than about a screen, and both are what the recovery banner and the inbox are drawn from.
 */

import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react'

import type { ActionRight } from '@kalareach/protocol'

import { ShellRights } from '../app/rights'
import { useApp } from '../app/state'
import { Toast } from '../components/ui'
import { failureMessage, follow } from '../host/port'
import {
  AccountGlyph,
  AttentionGlyph,
  HostsGlyph,
  SessionsGlyph,
  SettingsButton,
  TabBar,
  TopBar,
  type Destination
} from './components/chrome'
import { Account } from './views/Account'
import { Inbox } from './views/Inbox'
import { MobileHosts, MobileSessions } from './views/Places'
import { MobileSession } from './views/MobileSession'
import { MobileSettings } from './views/Settings'
import { VoiceRoute } from '../voice/VoiceRoute'
import type { Channel } from '../model/account'
import { useKeyboardInset, useLifecycle } from './useLifecycle'
import { useRebind } from './useRebind'
import { detectSurface, type Surface } from './platform'
import './mobile.css'

/** The four destinations. */
type Tab = 'attention' | 'sessions' | 'hosts' | 'account'

/**
 * Where the shell is: a destination, and the session open inside it when there is one, and whether
 * the settings are open over that session.
 */
interface Place {
  readonly tab: Tab
  readonly sessionId?: string
  readonly settings?: boolean
  /** The voice screen, over the sessions list: opened from it, and left the way a session is. */
  readonly voice?: boolean
}

const TABS: readonly Tab[] = ['attention', 'sessions', 'hosts', 'account']

/**
 * Where an address says to open.
 *
 * A notification about one session has to open that session, so the address the system hands the
 * application when a person taps it names where to go. An address that names nowhere opens the
 * inbox, which is where the application opens anyway.
 */
export function placeFromAddress(search: string): Place {
  const parameters = new URLSearchParams(search)
  const tab = parameters.get('tab')
  const sessionId = parameters.get('session')
  if (sessionId) return { tab: 'sessions', sessionId }
  const named = TABS.find((each) => each === tab)
  return { tab: named ?? 'attention' }
}

/**
 * What this build is, which decides only what the account screen may show. Where the device stands
 * with an account is the backend's to say, so it is read from the host port, not from the build.
 */
export interface MobileBuild {
  readonly channel: Channel
}

const DEFAULT_BUILD: MobileBuild = {
  channel: 'app_store'
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
  const [place, setPlace] = useState<Place>(() =>
    placeFromAddress(typeof window === 'undefined' ? '' : window.location.search)
  )
  // Where the connection stands, as the shell's first answer or a change since said it: null until
  // then, so neither the bar nor a session claims contact or its loss before anything has answered.
  const [connection, setConnection] = useState<{
    readonly connected: boolean
    readonly environmentId: string | null
    readonly reason: string | null
    readonly rights: readonly ActionRight[] | null
  } | null>(null)
  const [actionable, setActionable] = useState(0)
  const lifecycle = useLifecycle(storage)
  useRebind(lifecycle, connection?.connected === true)
  useKeyboardInset()

  useEffect(() => {
    document.documentElement.dataset.surface = resolved
    return () => {
      delete document.documentElement.dataset.surface
    }
  }, [resolved])

  // The last input device decides whether anything animates. A hardware keyboard is used dozens
  // of times a minute, and a transition on every key is a delay the person feels; a finger is not.
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

  // The connection is read once its listener is registered, so no change falls between the two.
  // Each change native code publishes carries the state and its reason, so nothing is read again,
  // and a change heard before the read answers is the newer one.
  useEffect(
    () =>
      follow(
        (listener) => port.onConnection(listener),
        () => port.connectionState(),
        (state) => {
          setConnection({
            connected: state.connected,
            environmentId: state.environment_id,
            reason: state.reason,
            rights: state.connected ? state.rights : null
          })
        },
        (failure) => {
          setConnection({
            connected: false,
            environmentId: null,
            reason: failureMessage(failure),
            rights: null
          })
        }
      ),
    [port]
  )

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
  const inVoice = place.tab === 'sessions' && place.voice === true && !inSession
  const settingsOpen = inSession && place.settings === true
  const title = inVoice
    ? 'Voice'
    : inSession
      ? 'Session'
      : place.tab === 'attention'
        ? 'Attention'
        : place.tab === 'sessions'
          ? 'Sessions'
          : place.tab === 'hosts'
            ? 'Hosts'
            : 'Account'

  const setSettings = useCallback((open: boolean) => {
    setPlace((current) => ({ ...current, settings: open }))
  }, [])
  const openVoice = useCallback(() => {
    setPlace({ tab: 'sessions', voice: true })
  }, [])

  // Android's system back leaves a session the same way the bar's control does, so the two are one
  // behaviour rather than two. It closes what is over the session first: with the settings open, a
  // back closes them, the session keeps its place in the history, and the next back leaves it.
  useEffect(() => {
    if (!inSession) return
    window.history.pushState({ kr: 'session' }, '')
  }, [inSession])
  useEffect(() => {
    if (!inSession) return
    const onPop = () => {
      if (settingsOpen) {
        setSettings(false)
        window.history.pushState({ kr: 'session' }, '')
      } else {
        setPlace({ tab: 'sessions' })
      }
    }
    window.addEventListener('popstate', onPop)
    return () => {
      window.removeEventListener('popstate', onPop)
    }
  }, [inSession, settingsOpen, setSettings])

  // The voice screen is left the way a session is: by the bar's control and by the system's back.
  useEffect(() => {
    if (!inVoice) return
    window.history.pushState({ kr: 'voice' }, '')
    const onPop = () => {
      setPlace({ tab: 'sessions' })
    }
    window.addEventListener('popstate', onPop)
    return () => {
      window.removeEventListener('popstate', onPop)
    }
  }, [inVoice])

  const shell = (
    <div className="m-shell" data-surface={resolved}>
      <TopBar
        title={title}
        surface={resolved}
        connection={connection}
        onBack={
          inSession || inVoice
            ? () => {
                setPlace({ tab: 'sessions' })
              }
            : undefined
        }
        backLabel="Back to sessions"
        action={
          inSession ? (
            <SettingsButton
              surface={resolved}
              onPress={() => {
                setSettings(true)
              }}
            />
          ) : undefined
        }
      />

      <main className="m-main" id="main" tabIndex={-1}>
        {place.tab === 'attention' ? (
          <Inbox surface={resolved} onOpenSession={openSession} onCounts={setActionable} />
        ) : null}
        {place.tab === 'sessions' && !inSession && !inVoice ? (
          <MobileSessions
            surface={resolved}
            onOpen={openSession}
            onOpenVoice={connection?.connected === true ? openVoice : undefined}
            connected={connection?.connected ?? null}
            environmentId={connection?.environmentId ?? null}
          />
        ) : null}
        {inVoice ? <VoiceRoute surface={resolved} embedded /> : null}
        {inSession && place.sessionId ? (
          <MobileSession
            sessionId={place.sessionId}
            surface={resolved}
            lifecycle={lifecycle}
            connected={connection?.connected ?? null}
          />
        ) : null}
        {place.tab === 'hosts' ? (
          <MobileHosts
            surface={resolved}
            connected={connection?.connected ?? null}
            environmentId={connection?.environmentId ?? null}
          />
        ) : null}
        {place.tab === 'account' ? <Account surface={resolved} channel={build.channel} /> : null}
      </main>

      <TabBar
        destinations={destinations}
        current={place.tab}
        surface={resolved}
        onChoose={(id) => {
          setPlace({ tab: id as Tab })
        }}
      />

      {inSession ? (
        <MobileSettings
          open={settingsOpen}
          onClose={() => {
            setSettings(false)
          }}
        />
      ) : null}

      <Toast message={toast} onDismiss={dismissToast} />
    </div>
  )
  return <ShellRights.Provider value={connection?.rights ?? null}>{shell}</ShellRights.Provider>
}
