/**
 * The voice screen: what a person is told before a call, and what they hold while one is running.
 *
 * Two screens, one component, because they are one flow. Before a call it is a choice: who will
 * hear this, what will be sent, and what the call is allowed to do. During a call it is a set of
 * controls, and the point of their arrangement is that the two things a person can stop are never
 * adjacent and never look alike.
 *
 * It reaches the host the way every other screen does, through `host/port.ts`. It holds no socket
 * and no connection: a voice screen that carried its own transport would be a second place the
 * boundary is enforced, and a boundary enforced in two places is enforced in neither.
 */

import { useCallback, useEffect, useId, useMemo, useRef, useState } from 'react'

import {
  CAPTURE_DISPLAY,
  STOP_MEANS,
  callLength,
  controlAvailable,
  rateWords,
  requestedSeconds,
  speechCouldHaveBeenHeard,
  type ContextRequest,
  type Delegation,
  type ProviderChoice,
  type RunningCall
} from './model'
import './voice.css'

/** What the screen can do, supplied by whatever is hosting it. */
export interface VoiceSurfaceActions {
  /** Starts a call. The offer is made natively; this screen never touches media. */
  readonly start: () => void
  /** Mutes or unmutes the person's own microphone. Local, and never awaits the broker. */
  readonly setMicrophoneMuted: (muted: boolean) => void
  /** Silences the model's voice. Local. Cancels nothing. */
  readonly stopPlayback: () => void
  /** Ends the call and revokes its grant. Local, and the host is told after. */
  readonly hangUp: () => void
  /** Cancels the current turn on a host. Typed, and it names the turn. */
  readonly cancelTask: (sessionId: string, turnId: string) => void
  /** Asks the host what it selected for the call. A read from the host; nothing is sent onward. */
  readonly readSelection: () => void
}

/** What the screen is looking at. */
export interface VoiceSurfaceProps {
  /** What the host answered about a call that does not exist yet, or null while it has not. */
  readonly choice: ProviderChoice | null
  /** The running call, or null before one starts. */
  readonly call: RunningCall | null
  /** The session and turn a cancellation would name, when the host has published one. */
  readonly currentTurn: { readonly sessionId: string; readonly turnId: string } | null
  /** True while a request this screen made is in flight. */
  readonly busy: boolean
  /**
   * What the last answer said, when it was not a call.
   *
   * A refusal, an unavailable service or a creation whose outcome is unknown are all answers, and
   * each one is shown in the host's own words rather than turned into a state the screen invented.
   */
  readonly notice: string | null
  readonly actions: VoiceSurfaceActions
}

/** The voice screen. */
export function VoiceSurface({
  choice,
  call,
  currentTurn,
  busy,
  notice,
  actions
}: VoiceSurfaceProps): React.ReactElement {
  if (call) {
    return <CallScreen call={call} currentTurn={currentTurn} busy={busy} notice={notice} actions={actions} />
  }
  if (choice) {
    return <ProviderChoiceScreen choice={choice} busy={busy} notice={notice} onStart={actions.start} />
  }
  return (
    <section className="kr-voice" aria-busy={busy}>
      <h1 className="kr-voice__title">Start a voice session</h1>
      <p className="kr-voice__refusal" role="status">
        {notice ?? 'Asking this host what a voice session would be allowed to do…'}
      </p>
    </section>
  )
}

/**
 * Everything a person is told before any audio is captured.
 *
 * KR-REQ-15.19 wants the provider and the selected context scope shown before voice starts, and
 * KR-REQ-15.09 wants the managed content access stated in the provider choice. Both live above the
 * start control, because a disclosure below the button that acts on it has already been skipped.
 * So does the rate, directly above it: starting is what accepts the rate, and the version on
 * screen is the one the start names.
 */
function ProviderChoiceScreen({
  choice,
  busy,
  notice,
  onStart
}: {
  readonly choice: ProviderChoice
  /** True while a start is in flight, so one press cannot become two calls. */
  readonly busy: boolean
  /** What the last answer said, when it was not a call. */
  readonly notice: string | null
  readonly onStart: () => void
}): React.ReactElement {
  const id = useId()
  const terms = choice.managed
  const seconds = terms ? requestedSeconds(terms) : null
  const startable = terms !== null && terms.enabled && seconds !== null

  return (
    <section className="kr-voice" aria-labelledby={`${id}-heading`}>
      <h1 id={`${id}-heading`} className="kr-voice__title">
        Start a voice session
      </h1>

      {terms ? (
        <dl className="kr-voice__provider">
          <dt>Voice model</dt>
          <dd>{terms.model}</dd>
          <dt>Brokered by</dt>
          <dd>{choice.brokerOrigin}</dd>
        </dl>
      ) : (
        <p className="kr-voice__refusal" role="status">
          {choice.unavailable}
        </p>
      )}

      {/* The deployed service's own words, listed rather than summarised. A second wording of the
          same facts is a second thing to keep true. */}
      {terms && (
        <section className="kr-voice__panel" aria-labelledby={`${id}-access`}>
          <h2 id={`${id}-access`}>What this gives access to</h2>
          <ul className="kr-voice__list">
            {terms.disclosure.map((line) => (
              <li key={line}>{line}</li>
            ))}
          </ul>
        </section>
      )}

      <section className="kr-voice__panel" aria-labelledby={`${id}-sessions`}>
        <h2 id={`${id}-sessions`}>Sessions this call can reach</h2>
        <ul className="kr-voice__list">
          {choice.sessions.map((session) => (
            <li key={session}>{choice.sessionNames[session] ?? session}</li>
          ))}
        </ul>
      </section>

      <section className="kr-voice__panel" aria-labelledby={`${id}-scope`}>
        <h2 id={`${id}-scope`}>What will be sent</h2>
        <ul className="kr-voice__list">
          {choice.context.map((item) => (
            <li key={item.kind}>
              <span className="kr-voice__kind">{item.kind.replace(/_/g, ' ')}</span>
              <span className="kr-voice__summary">{item.summary}</span>
            </li>
          ))}
        </ul>
        <p className="kr-voice__cap">
          This host sends at most {choice.tokenCap.toLocaleString()} tokens of it, and cuts what is
          selected to fit.
        </p>

        <h3 className="kr-voice__subhead">Not sent</h3>
        <ul className="kr-voice__list kr-voice__list--muted">
          {choice.withheld.map((item) => (
            <li key={item.kind}>
              <span className="kr-voice__kind">{item.summary}</span>
              <span className="kr-voice__summary">{item.reason}</span>
            </li>
          ))}
        </ul>
      </section>

      <section className="kr-voice__panel" aria-labelledby={`${id}-permits`}>
        <h2 id={`${id}-permits`}>What speaking will be allowed to do</h2>
        <ul className="kr-voice__list">
          {choice.permits.map((line) => (
            <li key={line}>{line}</li>
          ))}
        </ul>
        <p className="kr-voice__note">
          The host refuses anything not listed here.
          {choice.needsUnlockedScreen &&
            ' Some of these ask for your confirmation on the unlocked screen of this device each time.'}
        </p>
      </section>

      {terms && !terms.enabled && (
        <section className="kr-voice__panel" aria-labelledby={`${id}-closed`}>
          <h2 id={`${id}-closed`}>Managed voice is closed at the moment</h2>
          <p className="kr-voice__note">These still work:</p>
          <ul className="kr-voice__list">
            {terms.alternatives.map((line) => (
              <li key={line}>{line}</li>
            ))}
          </ul>
        </section>
      )}

      {terms && terms.enabled && seconds !== null && (
        <CostPanel id={`${id}-cost`} choice={choice} seconds={seconds} />
      )}

      {terms && terms.enabled && seconds === null && (
        <p className="kr-voice__refusal" role="status">
          The managed service allows no call length this screen can ask for, so a call cannot start
          from here.
        </p>
      )}

      {notice && (
        <p className="kr-voice__refusal" role="status">
          {notice}
        </p>
      )}

      {startable && (
        <button
          type="button"
          className="kr-voice__start"
          onClick={onStart}
          disabled={busy}
          aria-describedby={`${id}-cost-rate ${id}-cost-limits`}
        >
          {busy ? 'Starting…' : choice.previousRate ? 'Start at the new rate' : 'Start voice session'}
        </button>
      )}
    </section>
  )
}

/**
 * What a call costs, directly above the control that accepts it.
 *
 * When a start was refused because the rate moved on, the new rate is what this shows and the
 * one the person read before is named beside it, so nobody accepts a change they did not see.
 */
function CostPanel({
  id,
  choice,
  seconds
}: {
  readonly id: string
  readonly choice: ProviderChoice
  readonly seconds: number
}): React.ReactElement | null {
  const terms = choice.managed
  if (!terms) return null
  const words = rateWords(terms.rate)
  const ceiling = words.ceiling(seconds)
  const before = choice.previousRate ? rateWords(choice.previousRate) : null
  return (
    <section className="kr-voice__panel" aria-labelledby={id}>
      <h2 id={id}>What it costs</h2>
      {/* Announced whole: the new rate, the old one and what did not happen, so a screen reader
          user hears what they would now be accepting rather than only what changed. */}
      {before && (
        <p className="kr-voice__refusal" role="status">
          The rate changed after you read it. It is now {words.perSecond} a second, and was{' '}
          {before.perSecond}. Nothing was started or charged.
        </p>
      )}
      <p className="kr-voice__rate" id={`${id}-rate`}>
        {words.perSecond} a second{words.perMinute && <> ({words.perMinute} a minute)</>}
      </p>
      <p className="kr-voice__note" id={`${id}-limits`}>
        Every call is charged for at least {callLength(terms.rate.minimum_seconds)}. This call can
        last up to {callLength(seconds)}
        {ceiling ? <>, so it can cost at most {ceiling}.</> : '.'}
      </p>
    </section>
  )
}

/** The controls a person holds while a call is running. */
function CallScreen({
  call,
  currentTurn,
  busy,
  notice,
  actions
}: {
  readonly call: RunningCall
  readonly currentTurn: { readonly sessionId: string; readonly turnId: string } | null
  readonly busy: boolean
  readonly notice: string | null
  readonly actions: VoiceSurfaceActions
}): React.ReactElement {
  /**
   * The turn the open confirmation is about, not merely that one is open.
   *
   * A confirmation that read the current turn at the moment it was answered would cancel whatever
   * the host had moved on to while the question sat on screen. It names its turn when it opens, and
   * the host moving to another turn throws it away rather than hiding it: a question the person can
   * no longer see has not been answered, and it must not come back answered if the host returns to
   * the turn it was asked about.
   */
  const [confirmingCancel, setConfirmingCancel] = useState<{
    readonly sessionId: string
    readonly turnId: string
  } | null>(null)
  const [turnWhenAsked, setTurnWhenAsked] = useState(currentTurn)

  if (
    turnWhenAsked?.sessionId !== currentTurn?.sessionId ||
    turnWhenAsked?.turnId !== currentTurn?.turnId
  ) {
    setTurnWhenAsked(currentTurn)
    if (confirmingCancel) setConfirmingCancel(null)
  }

  const muted = call.capture === 'muted_by_person'
  const heard = speechCouldHaveBeenHeard(call.capture)
  const canCancel = controlAvailable('cancel_task', call) && currentTurn !== null
  const headingId = useId()

  const askRef = useRef<HTMLButtonElement | null>(null)
  const confirmRef = useRef<HTMLButtonElement | null>(null)
  const panelRef = useRef<HTMLElement | null>(null)
  const wasConfirming = useRef(false)

  // Focus follows the question and comes back to the control that asked it. A confirmation that
  // replaced the focused control without moving focus would leave a keyboard or screen-reader user
  // at the top of the document, reading the page again to find what they just pressed. When the
  // control that asked is no longer available, focus lands on the panel it belongs to instead of
  // on a button nothing can press.
  useEffect(() => {
    if (confirmingCancel) {
      confirmRef.current?.focus()
    } else if (wasConfirming.current) {
      const ask = askRef.current
      if (ask && !ask.disabled) ask.focus()
      else panelRef.current?.focus()
    }
    wasConfirming.current = confirmingCancel !== null
  }, [confirmingCancel])

  const cancel = useCallback(() => {
    // Checked again here, not only when the control was drawn: the host can become unreachable
    // while the question is on screen, and a cancellation that cannot be delivered must not be
    // reported to the person as one that was.
    if (!confirmingCancel || !controlAvailable('cancel_task', call)) return
    actions.cancelTask(confirmingCancel.sessionId, confirmingCancel.turnId)
    setConfirmingCancel(null)
  }, [actions, call, confirmingCancel])

  const admitted = useMemo(
    () => call.requests.filter((request) => request.outcome === 'admitted').length,
    [call.requests]
  )

  return (
    <section className="kr-voice kr-voice--live" aria-labelledby={headingId}>
      <h1 id={headingId} className="kr-voice__title">
        Voice session
      </h1>

      {/* The capture state is the first thing on the screen, because it is what decides whether
          anything spoken counted. */}
      <p
        className={`kr-voice__capture kr-voice__capture--${heard ? 'on' : 'off'}`}
        role="status"
        aria-live="polite"
      >
        {CAPTURE_DISPLAY[call.capture]}
      </p>
      {!heard && (
        <p className="kr-voice__refusal">
          Nothing spoken while the microphone was not carrying your voice can authorise an action.
        </p>
      )}

      {!call.brokerReachable && (
        <p className="kr-voice__refusal" role="status">
          The voice service is not answering. Mute, stopping the voice and hanging up still work, and
          so does everything that goes to the host.
        </p>
      )}

      {!call.hostReachable && (
        <p className="kr-voice__refusal" role="status">
          This device is not reaching the host. Mute, stopping the voice and hanging up still work;
          cancelling a turn and reading what the host selected do not, because both go to the host.
        </p>
      )}

      {/* The local controls. All three keep working when nothing else does. */}
      <div className="kr-voice__controls" role="group" aria-label="Call controls">
        <button
          type="button"
          className="kr-voice__control"
          aria-pressed={muted}
          onClick={() => actions.setMicrophoneMuted(!muted)}
        >
          {muted ? 'Unmute microphone' : 'Mute microphone'}
        </button>
        <button
          type="button"
          className="kr-voice__control"
          aria-pressed={!call.playing}
          onClick={actions.stopPlayback}
        >
          Stop the voice
        </button>
        <button type="button" className="kr-voice__control kr-voice__control--end" onClick={actions.hangUp}>
          End session
        </button>
      </div>
      <p className="kr-voice__note">{STOP_MEANS.playback}</p>

      {/* Deliberately separated from the three above, with its own heading, its own words and a
          confirmation step. Section 15 paragraph 13 says the interface must not let a person
          confuse stopping speech with cancelling work, and adjacency is how that confusion is
          usually built. */}
      <section className="kr-voice__panel kr-voice__panel--cancel" ref={panelRef} tabIndex={-1}>
        <h2>Cancel what the agent is doing</h2>
        <p className="kr-voice__note">{STOP_MEANS.task}</p>
        {!currentTurn && (
          <p className="kr-voice__note">
            The host has not said which turn the agent is on, so there is no turn to cancel from
            here.
          </p>
        )}
        {confirmingCancel ? (
          <div className="kr-voice__confirm">
            <button
              type="button"
              ref={confirmRef}
              className="kr-voice__control kr-voice__control--danger"
              disabled={!canCancel}
              onClick={cancel}
            >
              Cancel this turn
            </button>
            <button
              type="button"
              className="kr-voice__control"
              onClick={() => setConfirmingCancel(null)}
            >
              Keep it running
            </button>
          </div>
        ) : (
          <button
            type="button"
            ref={askRef}
            className="kr-voice__control"
            disabled={!canCancel}
            onClick={() => currentTurn && setConfirmingCancel(currentTurn)}
          >
            Cancel the current turn
          </button>
        )}
      </section>

      {/* What the host selected for this call. A read from the host, so it follows the host
          connection; it sends nothing to the voice service. */}
      <section className="kr-voice__panel" aria-label="Context">
        <h2>What the host selected for this call</h2>
        <button
          type="button"
          className="kr-voice__control"
          disabled={!controlAvailable('host_selection', call) || busy}
          onClick={actions.readSelection}
        >
          Show what the host selected
        </button>
        {call.requests.length > 0 && (
          <ul className="kr-voice__list">
            {call.requests.map((request) => (
              <li key={request.id} className="kr-voice__delegation">
                <span className="kr-voice__kind">{REQUEST_WORDS[request.outcome]}</span>
                {request.reason && <span className="kr-voice__summary">{request.reason}</span>}
              </li>
            ))}
          </ul>
        )}
      </section>

      {notice && (
        <p className="kr-voice__refusal" role="status">
          {notice}
        </p>
      )}

      <section className="kr-voice__panel" aria-label="Delegations">
        <h2>What the voice has asked for</h2>
        {call.delegations.length === 0 ? (
          <p className="kr-voice__note">Nothing yet.</p>
        ) : (
          <ul className="kr-voice__list">
            {call.delegations.map((delegation) => (
              <DelegationRow key={delegation.delegationId} delegation={delegation} />
            ))}
          </ul>
        )}
        {admitted > 0 && <p className="kr-voice__note">{call.admissionMeans}</p>}
      </section>
    </section>
  )
}

/** What each context outcome is called where a person reads it. */
const REQUEST_WORDS: Readonly<Record<ContextRequest['outcome'], string>> = {
  selected: 'Selected by the host',
  sent: 'Sent',
  accepted: 'Taken by the service',
  admitted: 'Acknowledged by the model',
  refused: 'Refused'
}

/** One delegation, with what the host actually said about it. */
function DelegationRow({ delegation }: { readonly delegation: Delegation }): React.ReactElement {
  const words: Record<Delegation['state'], string> = {
    announced: 'Heard',
    not_sent: 'Not sent to the host',
    submitted: 'Sent to the host',
    needs_confirmation: 'Needs your confirmation on this device’s unlocked screen',
    refused: 'Refused by the host',
    receipted: 'Done, with the host’s receipt'
  }
  return (
    <li className="kr-voice__delegation">
      <span className="kr-voice__kind">{words[delegation.state]}</span>
      {delegation.detail && <span className="kr-voice__summary">{delegation.detail}</span>}
    </li>
  )
}
