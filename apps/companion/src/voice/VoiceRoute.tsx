import { useMemo, useState, type ReactNode } from 'react'

import { VoiceSurface, type VoiceSurfaceActions } from './VoiceSurface'
import {
  type CaptureState,
  type ProviderChoice,
  type RunningCall
} from './model'
import type { Surface } from '../mobile/platform'

export const DEFAULT_PROVIDER_CHOICE: ProviderChoice = {
  model: 'gpt-live-1',
  brokerOrigin: 'https://reach.kala.to',
  disclosure: [
    'Audio travels directly between this device and the provider, not through this service.',
    'The provider and this service can process the speech and the context the host selects.',
    "This service's own channel to the provider still receives transcripts and copies of the audio. They are discarded before telemetry and never stored, which reduces what is kept rather than making it unreadable.",
    'Selected context and host results are sent as bounded requests. What the host selected can include project text, and this service and the provider both see it.',
    'A statement from the model that you confirmed something is not a confirmation. Actions that need one ask for it on the unlocked screen of this device.'
  ],
  context: [
    { kind: 'session_description', summary: 'Building the release', tokens: 120 },
    { kind: 'working_directory', summary: '~/work/kalareach', tokens: 20 }
  ],
  withheld: [
    { kind: 'file_contents', reason: 'not selected' },
    { kind: 'terminal_scrollback', reason: 'not selected' }
  ],
  tokenCap: 8000,
  sessions: ['s-1'],
  permits: ['navigate sessions', 'ask for status', 'brief you', 'compose a prompt']
}

export function VoiceRoute({
  surface
}: {
  readonly surface: Surface
}): ReactNode {
  const params = useMemo(() => {
    if (typeof window === 'undefined') return new URLSearchParams()
    return new URLSearchParams(window.location.search)
  }, [])

  const initialCall = useMemo((): RunningCall | null => {
    const stateParam = params.get('state')
    const callParam = params.get('call')
    if (!stateParam && !callParam) return null

    const capture: CaptureState =
      stateParam === 'muted' || stateParam === 'muted_by_person'
        ? 'muted_by_person'
        : stateParam === 'unavailable'
        ? 'unavailable'
        : stateParam === 'interrupted'
        ? 'interrupted'
        : stateParam === 'suspended' || stateParam === 'suspended_by_system'
        ? 'suspended_by_system'
        : stateParam === 'route_changing'
        ? 'route_changing'
        : 'capturing'

    const brokerReachable = params.get('broker') !== 'unreachable'
    const playing = params.get('playing') !== 'false'

    return {
      voiceSessionId: 'vs-1',
      callId: 'call-1',
      model: 'gpt-live-1',
      closesAtMs: 1_800_000,
      capture,
      playing,
      brokerReachable,
      delegations: [],
      requests: [],
      firstAudioMs: 410
    }
  }, [params])

  const [call, setCall] = useState<RunningCall | null>(initialCall)

  const choice = useMemo<ProviderChoice>(() => {
    if (params.get('over_cap') === '1') {
      return { ...DEFAULT_PROVIDER_CHOICE, tokenCap: 50 }
    }
    return DEFAULT_PROVIDER_CHOICE
  }, [params])

  const currentTurn = useMemo(() => {
    const session = params.get('session') ?? 's-1'
    const turn = params.get('turn') ?? 't-1'
    return { sessionId: session, turnId: turn }
  }, [params])

  const actions = useMemo<VoiceSurfaceActions>(
    () => ({
      start: () => {
        setCall({
          voiceSessionId: 'vs-1',
          callId: 'call-1',
          model: 'gpt-live-1',
          closesAtMs: 1_800_000,
          capture: 'capturing',
          playing: true,
          brokerReachable: true,
          delegations: [],
          requests: [],
          firstAudioMs: 410
        })
      },
      setMicrophoneMuted: (muted: boolean) => {
        setCall((current) =>
          current
            ? {
                ...current,
                capture: muted ? 'muted_by_person' : 'capturing'
              }
            : null
        )
      },
      stopPlayback: () => {
        setCall((current) => (current ? { ...current, playing: false } : null))
      },
      hangUp: () => {
        setCall(null)
      },
      cancelTask: (sessionId: string, turnId: string) => {
        void sessionId
        void turnId
      }
    }),
    []
  )

  return (
    <main id="main" tabIndex={-1} data-surface={surface}>
      <VoiceSurface
        choice={choice}
        call={call}
        currentTurn={currentTurn}
        actions={actions}
      />
    </main>
  )
}
