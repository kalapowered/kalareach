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
  ADMISSION_MEANS,
  CAPTURE_DISPLAY,
  STOP_MEANS,
  controlAvailable,
  selectedTokens,
  speechCouldHaveBeenHeard,
  withinCap,
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
}

/** What the screen is looking at. */
export interface VoiceSurfaceProps {
  readonly choice: ProviderChoice
  /** The running call, or null before one starts. */
  readonly call: RunningCall | null
  /** The session and turn a cancellation would name, when the host has published one. */
  readonly currentTurn: { readonly sessionId: string; readonly turnId: string } | null
  readonly actions: VoiceSurfaceActions
}

/** The voice screen. */
export function VoiceSurface({
  choice,
  call,
  currentTurn,
  actions
}: VoiceSurfaceProps): React.ReactElement {
  return call ? (
    <CallScreen call={call} currentTurn={currentTurn} actions={actions} />
  ) : (
    <ProviderChoiceScreen choice={choice} onStart={actions.start} />
  )
}

/**
 * Everything a person is told before any audio is captured.
 *
 * KR-REQ-15.19 wants the provider and the selected context scope shown before voice starts, and
 * KR-REQ-15.09 wants the managed content access stated in the provider choice. Both live above the
 * start control, because a disclosure below the button that acts on it has already been skipped.
 */
function ProviderChoiceScreen({
  choice,
  onStart
}: {
  readonly choice: ProviderChoice
  readonly onStart: () => void
}): React.ReactElement {
  const tokens = selectedTokens(choice)
  const fits = withinCap(choice)
  const disclosureId = useId()

  return (
    <section className="kr-voice" aria-labelledby={`${disclosureId}-heading`}>
      <h1 id={`${disclosureId}-heading`} className="kr-voice__title">
        Start a voice session
      </h1>

      <dl className="kr-voice__provider">
        <dt>Voice model</dt>
        <dd>{choice.model}</dd>
        <dt>Brokered by</dt>
        <dd>{choice.brokerOrigin}</dd>
      </dl>

      {/* The deployed service's own words, listed rather than summarised. A second wording of the
          same facts is a second thing to keep true. */}
      <section className="kr-voice__panel" aria-labelledby={`${disclosureId}-access`}>
        <h2 id={`${disclosureId}-access`}>What this gives access to</h2>
        <ul className="kr-voice__list">
          {choice.disclosure.map((line) => (
            <li key={line}>{line}</li>
          ))}
        </ul>
      </section>

      <section className="kr-voice__panel" aria-labelledby={`${disclosureId}-scope`}>
        <h2 id={`${disclosureId}-scope`}>What will be sent</h2>
        <ul className="kr-voice__list">
          {choice.context.map((item) => (
            <li key={item.kind}>
              <span className="kr-voice__kind">{item.kind.replace(/_/g, ' ')}</span>
              <span className="kr-voice__summary">{item.summary}</span>
            </li>
          ))}
        </ul>
        <p className={fits ? 'kr-voice__cap' : 'kr-voice__cap kr-voice__cap--over'}>
          About {tokens.toLocaleString()} of the {choice.tokenCap.toLocaleString()} tokens this host
          allows.
        </p>

        <h3 className="kr-voice__subhead">Not sent</h3>
        <ul className="kr-voice__list kr-voice__list--muted">
          {choice.withheld.map((item) => (
            <li key={item.kind}>
              <span className="kr-voice__kind">{item.kind.replace(/_/g, ' ')}</span>
              <span className="kr-voice__summary">{item.reason}</span>
            </li>
          ))}
        </ul>
      </section>

      <section className="kr-voice__panel" aria-labelledby={`${disclosureId}-permits`}>
        <h2 id={`${disclosureId}-permits`}>What speaking will be allowed to do</h2>
        <ul className="kr-voice__list">
          {choice.permits.map((line) => (
            <li key={line}>{line}</li>
          ))}
        </ul>
        <p className="kr-voice__note">
          Anything beyond these asks for your confirmation on the unlocked screen of this device. A
          statement from the model that you confirmed something is not a confirmation.
        </p>
      </section>

      <button type="button" className="kr-voice__start" onClick={onStart} disabled={!fits}>
        Start voice session
      </button>
    </section>
  )
}

/** The controls a person holds while a call is running. */
function CallScreen({
  call,
  currentTurn,
  actions
}: {
  readonly call: RunningCall
  readonly currentTurn: { readonly sessionId: string; readonly turnId: string } | null
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
          so does cancelling a turn, because that goes to the host. Sending context does not.
        </p>
      )}

      {!call.hostReachable && (
        <p className="kr-voice__refusal" role="status">
          This device is not reaching the host. Mute, stopping the voice and hanging up still work;
          cancelling a turn does not, because only the host can cancel one.
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
        {admitted > 0 && <p className="kr-voice__note">{ADMISSION_MEANS}</p>}
      </section>
    </section>
  )
}

/** One delegation, with what the host actually said about it. */
function DelegationRow({ delegation }: { readonly delegation: Delegation }): React.ReactElement {
  const words: Record<Delegation['state'], string> = {
    announced: 'Heard',
    submitted: 'Sent to the host',
    needs_confirmation: 'Waiting for your confirmation on this device',
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
