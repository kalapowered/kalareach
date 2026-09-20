/**
 * The voice screen's place in the application.
 *
 * Everything the screen shows comes back from somewhere else. The provider, the scope, the
 * disclosure and the grant's sentences are the host's answer to a preparation read; the session,
 * the model and the closing time are its answer to a start; the microphone, the speaker and the
 * first audio are what the call this device is holding reports. No action here changes what a
 * person sees until an answer has arrived, so a control that failed leaves the screen saying what
 * is true rather than what was attempted.
 */

import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react'

import { VoiceSurface, type VoiceSurfaceActions } from './VoiceSurface'
import {
  asCaptureState,
  choiceFromPreparation,
  runningCallFrom,
  type ContextRequest,
  type Delegation,
  type ProviderChoice,
  type RunningCall
} from './model'
import { useApp } from '../app/state'
import { failureMessage as portFailureMessage } from '../host/port'
import type { HostPort, VoiceCallState } from '../host/port'
import type { Surface } from '../mobile/platform'

/** The message to show for a failure, whatever shape it arrived in. */
function failureMessage(value: unknown): string {
  return portFailureMessage(value instanceof AskFailed ? value.payload : value)
}

/**
 * How long a call is asked to be authorised for, in seconds.
 *
 * Half an hour. It is what the request asks for; the service's answer carries the moment the call
 * actually closes, and that is what the screen counts against.
 */
const CALL_SECONDS = 1800

/**
 * How often the screen re-reads the call it is holding, in milliseconds.
 *
 * The microphone can be taken by a phone call, a route change or the system at any moment, and
 * what the screen says about capture decides whether anything spoken counted. Reading it from the
 * call itself is also what keeps it true when neither the service nor the host can be reached.
 */
const CAPTURE_POLL_MS = 500

/**
 * Runs one request and answers with what it did.
 *
 * A command that cannot even be attempted fails the same way as one the host refused, so every
 * caller here has exactly one failure path to show a person.
 */
function ask<T>(make: () => Promise<T>): Promise<T> {
  try {
    return make()
  } catch (error: unknown) {
    return Promise.reject(error instanceof Error ? error : new AskFailed(error))
  }
}

/** A failure that arrived as data rather than as an error, carried without being reshaped. */
class AskFailed extends Error {
  constructor(readonly payload: unknown) {
    super('that request could not be made')
    this.name = 'AskFailed'
  }
}

export function VoiceRoute({ surface }: { readonly surface: Surface }): ReactNode {
  const { port } = useApp()
  const params = useMemo(() => {
    if (typeof window === 'undefined') return new URLSearchParams()
    return new URLSearchParams(window.location.search)
  }, [])

  const [choice, setChoice] = useState<ProviderChoice | null>(null)
  const [call, setCall] = useState<RunningCall | null>(null)
  const [busy, setBusy] = useState(false)
  const [notice, setNotice] = useState<string | null>(null)

  /**
   * The platform's own touch target, resolved where the tokens look for it.
   *
   * `--target` is 44 on iOS and 48 on Android, and `styles/mobile.css` sets both from
   * `:root[data-surface]`. This screen is reached without the mobile shell around it, so it names
   * the surface on the root element itself; without that a phone would draw desktop-sized controls.
   */
  useEffect(() => {
    if (typeof document === 'undefined') return
    const root = document.documentElement
    const previous = root.dataset.surface
    root.dataset.surface = surface
    return () => {
      if (previous === undefined) delete root.dataset.surface
      else root.dataset.surface = previous
    }
  }, [surface])

  /**
   * Which input device the person last used.
   *
   * The same signal the desktop and mobile shells publish, set here because this screen is reached
   * without either of them around it. It decides whether a press moves: a pointer or a finger press
   * is a physical one and gets its movement, and a key press is not and does not.
   */
  useEffect(() => {
    if (typeof window === 'undefined') return
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

  // What a call would be, read before one exists. Nothing is created by asking, which is the whole
  // reason this read exists: a person can be told what a call would send and then decline it.
  useEffect(() => {
    let current = true
    void ask(() => port.voicePrepare({ session_ids: [], selected: [] }))
      .then((preparation) => {
        if (current) setChoice(choiceFromPreparation(preparation))
      })
      .catch((error: unknown) => {
        if (current) setNotice(failureMessage(error))
      })
    return () => {
      current = false
    }
  }, [port])

  const sessionIds = useMemo(() => {
    const named = params.get('session')
    return named ? [named] : []
  }, [params])

  const currentTurn = useMemo(() => {
    const session = params.get('session')
    const turn = params.get('turn')
    return session && turn ? { sessionId: session, turnId: turn } : null
  }, [params])

  // The call as the screen is holding it, so an action that runs later acts on the call that is
  // running now rather than on the one that was on screen when the handler was written.
  const held = useRef<RunningCall | null>(null)
  useEffect(() => {
    held.current = call
  }, [call])

  const applyLocalState = useCallback((state: VoiceCallState) => {
    setCall((running) => {
      if (!running) return running
      if (!state.running) return null
      return {
        ...running,
        capture: asCaptureState(state.capture),
        playing: state.playing,
        firstAudioMs: state.first_audio_ms
      }
    })
  }, [])

  // The call's own state, re-read while one is running. The native layer owns the microphone, and
  // the interruptions that matter most are the ones nothing asked for.
  useEffect(() => {
    if (!call) return
    let current = true
    const read = () => {
      void ask(() => port.voiceCallState())
        .then((state) => {
          if (current) applyLocalState(state)
        })
        .catch(() => {
          // A local read that failed says nothing new about the call; the next one answers.
        })
    }
    const timer = window.setInterval(read, CAPTURE_POLL_MS)
    return () => {
      current = false
      window.clearInterval(timer)
    }
  }, [applyLocalState, call, port])

  // A delegation the provider announced to this call. It is submitted to the host over this
  // device's own connection, never to the service, and what the row says is what the host answered.
  useEffect(() => {
    if (!call) return undefined
    return port.subscribe((event) => {
      const body = event.body as { kind?: string; delegation_id?: string } | null
      if (body?.kind !== 'voice_delegation' || !body.delegation_id) return
      const delegationId = body.delegation_id
      setCall((running) => (running ? withDelegation(running, delegationId, 'announced') : running))
      void submitDelegation(port, held, delegationId, setCall, setNotice)
    })
  }, [call, port])

  const actions = useMemo<VoiceSurfaceActions>(
    () => ({
      start: () => {
        if (busy) return
        setBusy(true)
        setNotice(null)
        void ask(() =>
          port.voiceStart(
            { sessionIds, durationSeconds: CALL_SECONDS, reasoningBudgetMinor: null },
            {}
          )
        )
          .then(async (settled) => {
            const outcome = settled.value?.outcome
            if (!outcome) {
              setNotice(
                'This host has not said whether that call was created. Nothing is running here.'
              )
              return
            }
            if ('unavailable' in outcome) {
              setNotice(outcome.unavailable.message)
              return
            }
            if ('creation_unknown' in outcome) {
              setNotice(outcome.creation_unknown.message)
              return
            }
            const session = outcome.started.session
            const state = await ask(() => port.voiceCallState()).catch(
              (): VoiceCallState => ({
                running: true,
                capture: 'unavailable',
                playing: false,
                first_audio_ms: null
              })
            )
            setCall(runningCallFrom(session, state, choice?.admissionMeans ?? ''))
          })
          .catch((error: unknown) => {
            setNotice(failureMessage(error))
          })
          .finally(() => {
            setBusy(false)
          })
      },

      setMicrophoneMuted: (muted: boolean) => {
        void ask(() => port.voiceSetMuted('microphone', muted))
          .then(applyLocalState)
          .catch((error: unknown) => {
            setNotice(failureMessage(error))
          })
      },

      stopPlayback: () => {
        void ask(() => port.voiceSetMuted('playback', true))
          .then(applyLocalState)
          .catch((error: unknown) => {
            setNotice(failureMessage(error))
          })
      },

      hangUp: () => {
        const running = held.current
        if (!running) return
        void ask(() => port.voiceStop(running.voiceSessionId, {}))
          .then((closure) => {
            if (closure.closed_locally) setCall(null)
            setNotice(
              closure.host_failure
                ? `This device's call is closed. The host was not told, so its grant may still be open: ${closure.host_failure.message}`
                : null
            )
          })
          .catch((error: unknown) => {
            setNotice(failureMessage(error))
          })
      },

      cancelTask: (sessionId: string, turnId: string) => {
        void ask(() =>
          port.composerInterrupt({ session_id: sessionId, turn_id: turnId }, { sessionId })
        )
          .then(() => {
            setNotice('The host was asked to cancel that turn. The voice keeps talking.')
          })
          .catch((error: unknown) => {
            setNotice(failureMessage(error))
          })
      },

      sendContext: () => {
        const running = held.current
        if (!running) return
        const requestId = `ctx-${running.requests.length + 1}`
        void ask(() =>
          port.voiceContext({
            voice_session_id: running.voiceSessionId,
            session_id: sessionIds[0] ?? running.voiceSessionId,
            selected: [],
            delegation_id: null
          })
        )
          .then(() => {
            setCall((current) =>
              current ? withRequest(current, requestId, 'voice.context', 'sent') : current
            )
          })
          .catch((error: unknown) => {
            setCall((current) =>
              current
                ? withRequest(current, requestId, 'voice.context', 'refused', failureMessage(error))
                : current
            )
          })
      }
    }),
    [applyLocalState, busy, choice, port, sessionIds]
  )

  return (
    <main id="main" tabIndex={-1} data-surface={surface}>
      <VoiceSurface
        choice={choice}
        call={call}
        currentTurn={currentTurn}
        busy={busy}
        notice={notice}
        actions={actions}
      />
    </main>
  )
}

/** Records one delegation at the state the host put it in. */
function withDelegation(
  call: RunningCall,
  delegationId: string,
  state: Delegation['state'],
  detail?: string
): RunningCall {
  const existing = call.delegations.findIndex((each) => each.delegationId === delegationId)
  const row: Delegation = {
    delegationId,
    offsetMs: existing >= 0 ? call.delegations[existing].offsetMs : 0,
    state,
    detail
  }
  const delegations =
    existing >= 0
      ? call.delegations.map((each, index) => (index === existing ? row : each))
      : [...call.delegations, row]
  return { ...call, delegations }
}

/** Records one context request at the outcome the service gave it. */
function withRequest(
  call: RunningCall,
  id: string,
  command: string,
  outcome: ContextRequest['outcome'],
  reason?: string
): RunningCall {
  const row: ContextRequest = { id, command, outcome, reason }
  const existing = call.requests.findIndex((each) => each.id === id)
  const requests =
    existing >= 0
      ? call.requests.map((each, index) => (index === existing ? row : each))
      : [...call.requests, row]
  return { ...call, requests }
}

/**
 * Submits one announced delegation to the host and records what it answered.
 *
 * Section 15 ¶7 puts this on the paired device's own connection to the host, not on the service's
 * channel. The provider's identifier travels as correlation data: it names which announcement this
 * answers and carries nothing the host acts on.
 */
async function submitDelegation(
  port: HostPort,
  held: { readonly current: RunningCall | null },
  delegationId: string,
  setCall: (update: (call: RunningCall | null) => RunningCall | null) => void,
  setNotice: (text: string | null) => void
): Promise<void> {
  const running = held.current
  if (!running) return
  try {
    const settled = await ask(() =>
      port.voiceDelegate(
      {
        voice_session_id: running.voiceSessionId,
        delegation_id: delegationId,
        offset_ms: 0,
        action: 'status',
        session_id: null,
        spoken_destination: null,
        approval: null,
        turn: null,
          confirmation: null
        },
        {}
      )
    )
    const outcome = settled.value?.outcome
    if (!outcome) {
      setCall((call) => (call ? withDelegation(call, delegationId, 'submitted') : call))
      return
    }
    if ('performed' in outcome) {
      setCall((call) =>
        call ? withDelegation(call, delegationId, 'receipted', outcome.performed.summary) : call
      )
      return
    }
    if ('admitted' in outcome) {
      setCall((call) =>
        call ? withDelegation(call, delegationId, 'submitted', outcome.admitted.note) : call
      )
      return
    }
    if ('confirmation_required' in outcome) {
      setCall((call) =>
        call
          ? withDelegation(
              call,
              delegationId,
              'needs_confirmation',
              outcome.confirmation_required.message
            )
          : call
      )
      return
    }
    setCall((call) =>
      call ? withDelegation(call, delegationId, 'refused', outcome.refused.message) : call
    )
  } catch (error: unknown) {
    setCall((call) =>
      call ? withDelegation(call, delegationId, 'refused', failureMessage(error)) : call
    )
    setNotice(failureMessage(error))
  }
}
