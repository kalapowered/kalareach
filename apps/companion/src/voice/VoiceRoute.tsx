/**
 * The voice screen's place in the application.
 *
 * Everything the screen shows comes back from somewhere else. The provider, the scope, the
 * disclosure and the grant's sentences are the host's answer to a preparation read; the session,
 * the model and the closing time are its answer to a start; the microphone and the speaker are
 * what the call this device is holding reports. No action here changes what a
 * person sees until an answer has arrived, so a control that failed leaves the screen saying what
 * is true rather than what was attempted.
 */

import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react'

import { VoiceGrantStep } from './VoiceGrantStep'
import { VoiceSurface, type VoiceSurfaceActions } from './VoiceSurface'
import {
  callAsReported,
  choiceFromPreparation,
  choiceWithRate,
  closureWords,
  endedWords,
  owedWords,
  requestedSeconds,
  runningCallFrom,
  serviceWords,
  type ContextRequest,
  type ProviderChoice,
  type RunningCall
} from './model'
import { useApp } from '../app/state'
import {
  failureCode,
  failureMessage as portFailureMessage,
  follow
} from '../host/port'
import type { VoiceCallState, VoiceClosure } from '../host/port'
import type { Surface } from '../mobile/platform'

/** The message to show for a failure, whatever shape it arrived in. */
function failureMessage(value: unknown): string {
  return portFailureMessage(value instanceof AskFailed ? value.payload : value)
}


/**
 * How often the screen re-reads the call it is holding, in milliseconds.
 *
 * The microphone can be taken by a phone call, a route change or the system at any moment, and
 * what the screen says about capture decides whether anything spoken counted. Reading it from the
 * call itself is also what keeps it true when neither the service nor the host can be reached.
 */
const CAPTURE_POLL_MS = 500

/** How often the screen re-reads what is owed to a host while a revocation is, in milliseconds. */
const OWED_POLL_MS = 5_000

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

export function VoiceRoute({
  surface,
  embedded = false
}: {
  readonly surface: Surface
  /** True inside the phone's shell, which has a main region of its own. */
  readonly embedded?: boolean
}): ReactNode {
  const { port } = useApp()
  const params = useMemo(() => {
    if (typeof window === 'undefined') return new URLSearchParams()
    return new URLSearchParams(window.location.search)
  }, [])

  const [choice, setChoice] = useState<ProviderChoice | null>(null)
  /**
   * The host's words when it would not prepare a call because this device holds no voice grant for
   * the sessions asked about, and none otherwise. While it is set the person is asked to allow
   * voice instead of being shown a call that cannot start.
   */
  const [needsGrant, setNeedsGrant] = useState<string | null>(null)
  /** The sessions the person allowed voice for here, which the preparation is then asked about. */
  const [allowed, setAllowed] = useState<readonly string[] | null>(null)
  const [call, setCall] = useState<RunningCall | null>(null)
  const [busy, setBusy] = useState(false)
  /**
   * Whether this screen's own start is waiting for the host's answer, which is when it can be given
   * up from here. It ends the moment the host answers, while `busy` goes on until what the answer
   * means has been shown: the preparation read again, or the call's state.
   */
  const [waitingForHost, setWaitingForHost] = useState(false)
  const [notice, setNotice] = useState<string | null>(null)
  /**
   * What this device last said while it held no call: the warning before a start, what an earlier
   * call left the host to hold open, and, for a call that ended while no screen was looking, how.
   */
  const [left, setLeft] = useState<VoiceCallState | null>(null)
  /** How the call that ended before this screen was shown ended, said once, when it is shown. */
  const [endedBefore, setEndedBefore] = useState<string | null>(null)
  /**
   * Whether the device is busy with a call that does not run yet: one this screen did not ask for,
   * or one it asked for and was loaded again before the host answered. There may be no call to name.
   */
  const [setUp, setSetUp] = useState(false)
  /** Whether what the device is busy with is being ended, so that nothing more can be asked of it. */
  const [endingSetUp, setEndingSetUp] = useState(false)
  /** Whether the last reading found the device setting a call up, to say how that ended. */
  const settingUpBefore = useRef(false)
  /**
   * True while this screen's own start waits for the host. The start tells its own answer, so what
   * the device is read to say meanwhile does not describe the start again, in other words.
   */
  const starting = useRef(false)
  /** True while this screen's own hang-up is waiting for the host, which says its own words. */
  const hangingUp = useRef(false)
  /**
   * How many times a call has left the screen. Focus goes to the heading of what replaces it: the
   * control that was pressed is gone, and focus left on nothing would send a keyboard or
   * screen-reader user back to the top of the document.
   */
  const [leftCount, setLeftCount] = useState(0)

  /**
   * Whether this device's connection to the host is carrying requests.
   *
   * The voice service is a different connection, and what the call reports about its own control
   * channel is the only thing that says whether that one is answering. Cancelling a turn and
   * reading what the host selected are requests to the host, so they follow this and nothing the
   * voice service does, which is what section 15 ¶10 asks for.
   */
  const [hostReachable, setHostReachable] = useState(true)

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

  // The session this screen was opened for, when an address named one. The preparation is asked
  // about that selection, and a start then names exactly the sessions the preparation answered.
  const named = useMemo(() => {
    const one = params.get('session')
    return one ? [one] : []
  }, [params])
  const sessionIds = allowed ?? named

  // What a call would be, read before one exists. Nothing is created by asking, which is the whole
  // reason this read exists: a person can be told what a call would send and then decline it.
  const prepare = useCallback(
    () =>
      ask(() => port.voicePrepare({ session_ids: sessionIds, selected: [] })).then(
        async (preparation) => {
          const choice = choiceFromPreparation(preparation)
          // The host's own names for the sessions, where it gives them. A name it does not give
          // is shown as the identifier rather than guessed at.
          const named = await ask(() => port.sessionList({})).then(
            (list) =>
              Object.fromEntries(
                list.sessions
                  .filter((session) => choice.sessions.includes(session.session_id))
                  .map((session) => [session.session_id, `Session ${session.display_number}`])
              ),
            () => ({})
          )
          return { ...choice, sessionNames: named }
        }
      ),
    [port, sessionIds]
  )

  useEffect(() => {
    let current = true
    void prepare()
      .then((prepared) => {
        if (!current) return
        setNeedsGrant(null)
        setChoice(prepared)
      })
      .catch((error: unknown) => {
        if (!current) return
        // A host that holds no voice grant for this device is not a failure to report: it is the
        // first question, and the person answers it.
        if (failureCode(error instanceof AskFailed ? error.payload : error) === 'PERMISSION_DENIED') {
          setNeedsGrant(failureMessage(error))
          return
        }
        setNotice(failureMessage(error))
      })
    return () => {
      current = false
    }
  }, [prepare])

  // This screen reads no agent, so it holds no turn. Cancelling one needs the turn the session's
  // worker reports now, with the instance and binding it was read at; one remembered from an
  // address would go stale the moment the agent moved on.
  const currentTurn = null

  // The call as the screen is holding it, so an action that runs later acts on the call that is
  // running now rather than on the one that was on screen when the handler was written.
  const held = useRef<RunningCall | null>(null)
  useEffect(() => {
    held.current = call
  }, [call])
  const shown = useRef<ProviderChoice | null>(null)
  useEffect(() => {
    shown.current = choice
  }, [choice])

  /**
   * Takes what the device says of its call.
   *
   * The call is the application's, not this screen's: it runs, and it ends, with no screen
   * looking. So a call the device holds is taken up whoever asked for it (a screen that is loaded
   * again finds the call it left), a call the screen held that the device no longer holds is
   * over, and said to be over in the device's words, and what an ended call left is kept for the
   * person to read before they start another.
   */
  const settle = useCallback((state: VoiceCallState) => {
    const described = state.session
    if (state.running && described !== null) {
      settingUpBefore.current = false
      setSetUp(false)
      setEndingSetUp(false)
      setCall((running) =>
        running ? callAsReported(running, state) : runningCallFrom(described, state, '')
      )
      return
    }
    setLeft(state)
    // A call being set up, or ended, is read again until it runs or is over. It may have no
    // descriptor yet, so the device's own word that it is busy decides.
    const busy = state.setting_up || described !== null
    // This screen's own start tells its own answer, and a call it holds is ended by its own
    // hang-up or by the device's own news: reading the device meanwhile describes neither again.
    if (starting.current) return
    if (busy) {
      if (held.current !== null) return
      settingUpBefore.current = true
      setSetUp(true)
      setEndingSetUp(state.ending)
      return
    }
    const watched = settingUpBefore.current
    settingUpBefore.current = false
    setSetUp(false)
    setEndingSetUp(false)
    if (held.current !== null || watched) {
      setCall(null)
      setLeftCount((count) => count + 1)
      if (!hangingUp.current) {
        setNotice(
          state.ended
            ? endedWords(state.ended, shown.current?.sessionNames ?? {})
            : 'The call ended.'
        )
      }
    }
  }, [])

  // What the device holds, read when the screen is shown: a call that is running is taken up, and
  // what the last one left is shown before a start.
  useEffect(() => {
    let current = true
    void ask(() => port.voiceCallState())
      .then((state) => {
        if (!current) return
        if (!state.running && !state.setting_up && state.session === null && state.ended) {
          setEndedBefore(endedWords(state.ended))
        }
        settle(state)
      })
      .catch(() => {
        // A local read that failed says nothing of the call; the screen starts as it would have.
      })
    return () => {
      current = false
    }
  }, [port, settle])

  // The call's own state, re-read while one runs or is being set up, and while the voice service
  // has still to say whether it closed the call that ended. The native layer owns the microphone,
  // and the interruptions that matter most are the ones nothing asked for.
  // The service's answer about an earlier call may arrive as something owed after a later call has
  // replaced that call's record, so the device's word that something is still finalising keeps the
  // screen reading as well.
  const reading =
    call !== null || setUp || left?.ended?.broker === 'pending' || left?.finalising === true
  useEffect(() => {
    if (!reading) return
    let current = true
    const read = () => {
      void ask(() => port.voiceCallState())
        .then((state) => {
          if (current) settle(state)
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
  }, [port, reading, settle])

  // What is owed to a host may be settled while no call runs: the host is reached again, and the
  // device asks it once more. The screen reads again every few seconds while a revocation is owed,
  // so it does not go on saying that a grant may be open once the host has said it is not.
  const revocationOwed = (left?.owed ?? []).some((owed) => owed.kind === 'revocation')
  useEffect(() => {
    if (!revocationOwed) return
    let current = true
    const timer = window.setInterval(() => {
      void ask(() => port.voiceCallState())
        .then((state) => {
          if (current) settle(state)
        })
        .catch(() => undefined)
    }, OWED_POLL_MS)
    return () => {
      current = false
      window.clearInterval(timer)
    }
  }, [port, revocationOwed, settle])

  // What this device owes lapses by itself, and the device stops saying it then: the screen reads
  // again at the first lapse it is waiting for, so a warning does not outlive what it warns of.
  const nextLapse = useMemo(() => {
    const ends = (left?.owed ?? []).map((owed) => owed.until_ms)
    return ends.length === 0 ? null : Math.min(...ends)
  }, [left])
  const [lapseTries, setLapseTries] = useState(0)
  useEffect(() => {
    if (nextLapse === null) return
    let current = true
    let retry: number | undefined
    const timer = window.setTimeout(
      () => {
        void ask(() => port.voiceCallState())
          .then((state) => {
            if (current) settle(state)
          })
          .catch(() => {
            // A read that failed leaves the warning standing, and is asked again.
            if (current) retry = window.setTimeout(() => setLapseTries((n) => n + 1), 2_000)
          })
      },
      // A little after the lapse, and never longer than a timer can hold.
      Math.min(Math.max(nextLapse - Date.now(), 0) + 50, 2_000_000_000)
    )
    return () => {
      current = false
      window.clearTimeout(timer)
      if (retry !== undefined) window.clearTimeout(retry)
    }
  }, [lapseTries, nextLapse, port, settle])

  /** What the last call left, as lines a person reads before starting another. */
  const aftermath = useMemo(() => {
    const lines: string[] = []
    if (endedBefore !== null) lines.push(endedBefore)
    for (const owed of left?.owed ?? []) lines.push(owedWords(owed))
    const service = left?.ended ? serviceWords(left.ended) : null
    if (service !== null) lines.push(service)
    if (left?.warning) lines.push(left.warning)
    return lines
  }, [endedBefore, left])

  // Whether this device is reaching the host. The backend publishes the connection's state, and
  // cancelling a turn is the one control that depends on it, so the screen follows the answer
  // rather than assuming the connection it started with is still there. The state is read once
  // the listener is registered, and a change heard before the read answers is the newer one.
  useEffect(
    () =>
      follow(
        (listener) => port.onConnection(listener),
        () => port.connectionState(),
        (state) => {
          setHostReachable(state.connected)
        },
        () => {
          setHostReachable(false)
        }
      ),
    [port]
  )

  /**
   * Whether a read of the device is owed after an end, until one has succeeded: what the end left
   * owed is only known from that read, and the person is told it as soon as it is.
   */
  const [leftUnread, setLeftUnread] = useState(false)
  useEffect(() => {
    if (!leftUnread) return
    let current = true
    let retry: number | undefined
    const read = () => {
      void ask(() => port.voiceCallState())
        .then((state) => {
          if (!current) return
          settle(state)
          setLeftUnread(false)
        })
        .catch(() => {
          // The read failed, and what was left owed is not yet known: ask again.
          if (current) retry = window.setTimeout(read, 1_000)
        })
    }
    read()
    return () => {
      current = false
      if (retry !== undefined) window.clearTimeout(retry)
    }
  }, [leftUnread, port, settle])

  /**
   * Asks the device to end its call, named or not, and says what it did in its own words when the
   * call was named: whether the microphone stopped here, and whether the host confirmed that it
   * withdrew the grant. A call that was not named is a setup, whose end the device says itself
   * when it is done. What the end left is read once those words are said, and adds none.
   */
  const endTheCall = useCallback(
    (
      voiceSessionId: string | null,
      closed: (closure: VoiceClosure) => void,
      refused: () => void = () => undefined
    ) => {
      hangingUp.current = true
      void ask(() => port.voiceStop(voiceSessionId, {}))
        .then((closure) => {
          closed(closure)
          setNotice(
            voiceSessionId === null ? null : closureWords(closure, shown.current?.sessionNames ?? {})
          )
        })
        .catch((error: unknown) => {
          refused()
          setNotice(failureMessage(error))
        })
        .finally(() => {
          hangingUp.current = false
          setLeftUnread(true)
        })
    },
    [port]
  )

  const actions = useMemo<VoiceSurfaceActions>(
    () => ({
      start: () => {
        // A managed call starts only under terms the person was shown: the start names the
        // version of the rate on screen, and there is no start without one.
        const terms = choice?.managed
        if (busy || !terms) return
        const seconds = requestedSeconds(terms)
        if (seconds === null) {
          setNotice('The managed service allows no call length this screen can ask for.')
          return
        }
        setBusy(true)
        setWaitingForHost(true)
        setNotice(null)
        starting.current = true
        const shown = choice
        void ask(() =>
          port.voiceStart(
            {
              sessionIds: shown.sessions,
              durationSeconds: seconds,
              reasoningBudgetMinor: null,
              prepared: shown.prepared,
              expectedRateVersion: terms.rate.version
            },
            {}
          )
        )
          .then(async (settled) => {
            setWaitingForHost(false)
            const outcome = settled.value?.outcome
            if (!outcome) {
              setNotice('The host never said whether it created that call.')
              // What the device then says of the end is its own words: whether the media stopped
              // and what is owed are not for this screen to guess.
              void ask(() => port.voiceCallState()).then(
                (state) => {
                  settle(state)
                  if (state.ended) setNotice(endedWords(state.ended))
                },
                () => undefined
              )
              return
            }
            if ('preparation_changed' in outcome) {
              // Nothing was started. What a call would be is read again and shown, and starting
              // is the person's decision again.
              setNotice(
                'What this call would reach or do changed after you read it, so nothing was started. It is shown again below.'
              )
              await prepare().then(setChoice, (error: unknown) => {
                setChoice(null)
                setNotice(failureMessage(error))
              })
              return
            }
            if ('rate_changed' in outcome) {
              // Nothing was started, held or charged. The new rate replaces the one on screen,
              // the old one stays beside it, and starting again is the person's decision.
              setChoice((current) =>
                current ? choiceWithRate(current, outcome.rate_changed.rate) : current
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
                setting_up: false,
                ending: false,
                capture: 'unavailable',
                playing: false,
                control: 'none',
                host: 'reachable',
                session: null,
                ended: null,
                delegations: [],
                warning: null,
                owed: [],
                finalising: false
              })
            )
            setLeft(null)
            setEndedBefore(null)
            setCall(runningCallFrom(session, state, terms.admission_note))
          })
          .catch((error: unknown) => {
            setNotice(failureMessage(error))
            void ask(() => port.voiceCallState()).then(settle, () => undefined)
          })
          .finally(() => {
            starting.current = false
            setBusy(false)
            setWaitingForHost(false)
            setEndingSetUp(false)
          })
      },

      setMicrophoneMuted: (muted: boolean) => {
        void ask(() => port.voiceSetMuted('microphone', muted))
          .then(settle)
          .catch((error: unknown) => {
            setNotice(failureMessage(error))
          })
      },

      stopPlayback: () => {
        void ask(() => port.voiceSetMuted('playback', true))
          .then(settle)
          .catch((error: unknown) => {
            setNotice(failureMessage(error))
          })
      },

      hangUp: () => {
        const running = held.current
        if (!running) return
        endTheCall(running.voiceSessionId, (closure) => {
          if (closure.closed_locally) {
            setCall(null)
            setLeftCount((count) => count + 1)
          }
        })
      },

      // Ends what the device is making when there is no call to name yet, and a call being made
      // that this screen was loaded again to find.
      endSetup: () => {
        // The device is still busy until it says so: the stop is answered at once, and the call the
        // host may yet turn out to have made is ended after it. The screen goes on reading. When
        // this screen's own start is the one waiting for the host, the start is still waiting
        // when the stop is answered, and the control says the end has begun until the start is over.
        const own = starting.current
        if (own) setEndingSetUp(true)
        endTheCall(
          null,
          () => undefined,
          () => {
            if (own) setEndingSetUp(false)
          }
        )
      },

      cancelTask: (turn) => {
        void ask(() =>
          port.composerInterrupt({
            target: {
              subject: { session_id: turn.sessionId, application_instance_id: turn.instanceId },
              binding_revision: turn.bindingRevision
            },
            turn_id: turn.turnId
          })
        )
          .then(() => {
            setNotice('The host was asked to cancel that turn. The voice keeps talking.')
          })
          .catch((error: unknown) => {
            setNotice(failureMessage(error))
          })
      },

      readSelection: () => {
        const running = held.current
        if (!running) return
        const requestId = `ctx-${running.requests.length + 1}`
        // The session this screen was opened for, or the first one the call was bound to. A voice
        // session is not a terminal session, so its identifier is never sent as one.
        const sessionId = sessionIds[0] ?? running.sessions[0]
        if (!sessionId) {
          setCall((current) =>
            current
              ? withRequest(
                  current,
                  requestId,
                  'voice.context',
                  'refused',
                  'This call reaches no session to select context from.'
                )
              : current
          )
          return
        }
        void ask(() =>
          port.voiceContext({
            voice_session_id: running.voiceSessionId,
            session_id: sessionId,
            selected: [],
            delegation_id: null
          })
        )
          .then((selection) => {
            // A read from the host, and nothing more: what the host selected for the call. It
            // says nothing about the voice service, which this read never reaches.
            const tokens = selection.selection.text_tokens
            setCall((current) =>
              current
                ? withRequest(
                    current,
                    requestId,
                    'voice.context',
                    'selected',
                    `${tokens.toLocaleString()} tokens from this session`
                  )
                : current
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
    [busy, choice, endTheCall, port, prepare, sessionIds, settle]
  )

  if (needsGrant !== null && !call) {
    return (
      <Region embedded={embedded} surface={surface}>
        <VoiceGrantStep
          port={port}
          refusal={needsGrant}
          named={named}
          onAllowed={(ids) => {
            setNeedsGrant(null)
            setAllowed(ids)
          }}
        />
      </Region>
    )
  }

  return (
    <Region embedded={embedded} surface={surface}>
      <VoiceSurface
        choice={choice}
        call={
          call && {
            ...call,
            // The host the call belongs to is reached when this application is reaching a host and
            // the call itself has not lost the one it was made with.
            hostReachable: hostReachable && call.callHost !== 'lost',
            admissionMeans: call.admissionMeans || (choice?.managed?.admission_note ?? '')
          }
        }
        currentTurn={currentTurn}
        busy={busy}
        waiting={waitingForHost}
        notice={notice}
        aftermath={aftermath}
        settingUp={setUp && !call}
        ending={endingSetUp}
        focusToken={leftCount}
        actions={actions}
      />
    </Region>
  )
}

/** The screen's region: the page's main one, or a plain one inside a shell that has its own. */
function Region({
  embedded,
  surface,
  children
}: {
  readonly embedded: boolean
  readonly surface: Surface
  readonly children: ReactNode
}): ReactNode {
  if (embedded) return <div data-surface={surface}>{children}</div>
  return (
    <main id="main" tabIndex={-1} data-surface={surface}>
      {children}
    </main>
  )
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
