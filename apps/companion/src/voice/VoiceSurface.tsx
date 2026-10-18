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

import { useCallback, useEffect, useId, useLayoutEffect, useMemo, useRef, useState } from 'react'

import {
  CAPTURE_DISPLAY,
  NOT_ACTED_ON_WORDS,
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

/**
 * The turn a cancellation names: the instance running it, the binding revision it was read at, and
 * the turn itself. The host refuses a cancellation whose binding has since moved, so a turn read
 * before the agent moved on cancels nothing it was not about.
 */
export interface CurrentTurn {
  readonly sessionId: string
  readonly instanceId: string
  readonly bindingRevision: string
  readonly turnId: string
}

/** Whether two turns are the same turn at the same binding. */
function sameTurn(a: CurrentTurn | null, b: CurrentTurn | null): boolean {
  if (a === null || b === null) return a === b
  return (
    a.sessionId === b.sessionId &&
    a.instanceId === b.instanceId &&
    a.bindingRevision === b.bindingRevision &&
    a.turnId === b.turnId
  )
}

/** What a person is told while the device ends what it was making, on either screen that says so. */
const ENDING_WORDS = 'This device is ending its call. This screen changes when that is done.'

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
  /**
   * Ends what the device is making when there is no call to name yet, whether the device found
   * it or this screen's own start is still waiting for the host. Local, and the host is asked
   * after, as a hang-up is.
   */
  readonly endSetup: () => void
  /** Cancels the current turn on a host. Typed, and it names the turn. */
  readonly cancelTask: (turn: CurrentTurn) => void
  /** Asks the host what it selected for the call. A read from the host; nothing is sent onward. */
  readonly readSelection: () => void
}

/** What the screen is looking at. */
export interface VoiceSurfaceProps {
  /** What the host answered about a call that does not exist yet, or null while it has not. */
  readonly choice: ProviderChoice | null
  /** The running call, or null before one starts. */
  readonly call: RunningCall | null
  /** The turn a cancellation would name, when the host has published one. */
  readonly currentTurn: CurrentTurn | null
  /** True while a request this screen made is in flight. */
  readonly busy: boolean
  /**
   * True while this screen's own start waits for the host's answer, which is the only time it can
   * be given up from here: before the host has answered there may be a call to end that no one can
   * name yet, and after it there is a call, or nothing.
   */
  readonly waiting?: boolean
  /**
   * What the last answer said, when it was not a call.
   *
   * A refusal, an unavailable service or a creation whose outcome is unknown are all answers, and
   * each one is shown in the host's own words rather than turned into a state the screen invented.
   */
  readonly notice: string | null
  /**
   * What the last call left, in words: how it ended when no screen was looking, what this device
   * could not finish and the host may still hold open, and the warning a person is given before the
   * next start. Shown before a call and never in place of what the person is deciding.
   */
  readonly aftermath?: readonly string[]
  /**
   * Whether the device is busy with a call that does not run: making one, which this screen is
   * asked to say instead of offering a second start, or ending one. There may be no call to name.
   */
  readonly settingUp?: boolean
  /**
   * Whether what the device holds is being ended, so that nothing more can be asked of it: the
   * setup screen says so, and so does the control that gives up this screen's own start.
   */
  readonly ending?: boolean
  /**
   * Counts the calls that have left this screen. A screen that appears after one takes focus, so
   * that the control that was pressed going away does not leave focus on nothing.
   */
  readonly focusToken?: number
  readonly actions: VoiceSurfaceActions
}

/** The voice screen. */
export function VoiceSurface({
  choice,
  call,
  currentTurn,
  busy,
  waiting = false,
  notice,
  aftermath = [],
  settingUp = false,
  ending = false,
  focusToken = 0,
  actions
}: VoiceSurfaceProps): React.ReactElement {
  if (call) {
    return <CallScreen call={call} currentTurn={currentTurn} busy={busy} notice={notice} actions={actions} />
  }
  if (settingUp) {
    return <SettingUpScreen ending={ending} notice={notice} onEnd={actions.endSetup} />
  }
  if (choice) {
    return (
      <ProviderChoiceScreen
        choice={choice}
        busy={busy}
        waiting={waiting}
        ending={ending}
        notice={notice}
        aftermath={aftermath}
        focusOnShow={focusToken > 0}
        onStart={actions.start}
        onEnd={actions.endSetup}
      />
    )
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
 * The screen while the device holds a call that does not run: one it is making, or one it is
 * ending.
 *
 * It offers no second start: the device holds one call at a time, and a start made now would be
 * turned away. It says what is true, and no more: this device cannot tell the screen what its
 * microphone is doing before a call runs, so it says nothing of it. While a call is being made the
 * one thing a person can do is end it, which needs no call to be named; once the end has begun
 * there is nothing more to ask, and the screen only says so.
 */
function SettingUpScreen({
  ending,
  notice,
  onEnd
}: {
  readonly ending: boolean
  readonly notice: string | null
  readonly onEnd: () => void
}): React.ReactElement {
  const id = useId()
  const heading = useRef<HTMLHeadingElement | null>(null)
  const wasEnding = useRef(ending)
  // The control that was pressed goes when the end begins, so focus goes to what says so: left on
  // nothing, a keyboard or screen-reader user would be sent back to the top of the document.
  useEffect(() => {
    if (ending && !wasEnding.current) heading.current?.focus()
    wasEnding.current = ending
  }, [ending])
  return (
    <section className="kr-voice" aria-labelledby={`${id}-heading`}>
      <h1 id={`${id}-heading`} className="kr-voice__title" ref={heading} tabIndex={-1}>
        {ending ? 'Ending a voice session' : 'Starting a voice session'}
      </h1>
      <p className="kr-voice__note" role="status">
        {ending ? ENDING_WORDS : "This device is making a call. The call's controls appear here when it runs."}
      </p>
      {notice && (
        <p className="kr-voice__refusal" role="status">
          {notice}
        </p>
      )}
      {!ending && (
        <div className="kr-voice__controls">
          <button type="button" className="kr-voice__control kr-voice__control--end" onClick={onEnd}>
            End the call
          </button>
        </div>
      )}
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
  waiting,
  ending,
  notice,
  aftermath,
  focusOnShow,
  onStart,
  onEnd
}: {
  readonly choice: ProviderChoice
  /** True while a start is in flight, so one press cannot become two calls. */
  readonly busy: boolean
  /** True while the start waits for the host's answer, so that it can be given up. */
  readonly waiting: boolean
  /** Whether the start in flight has been given up and is being ended. */
  readonly ending: boolean
  /** What the last answer said, when it was not a call. */
  readonly notice: string | null
  /** What the last call left. */
  readonly aftermath: readonly string[]
  /** Whether a call has just left this screen, so that focus goes to its heading. */
  readonly focusOnShow: boolean
  readonly onStart: () => void
  /** Gives up the start in flight, without naming a call: there may be none to name yet. */
  readonly onEnd: () => void
}): React.ReactElement {
  const id = useId()
  const heading = useRef<HTMLHeadingElement | null>(null)
  const takeFocus = useRef(focusOnShow)
  useEffect(() => {
    if (takeFocus.current) heading.current?.focus()
  }, [])
  const end = useRef<HTMLButtonElement | null>(null)
  // A start waits for the host as long as the host takes. The control that gives it up appears
  // beside the one that was pressed, which at the largest text sizes is a row lower, so it is
  // brought into view. Focus does not move to it: a key pressed twice would end the call it began.
  useEffect(() => {
    if (waiting) end.current?.scrollIntoView({ block: 'nearest' })
  }, [waiting])
  // The control that was pressed is disabled when the end begins, so focus goes to the words beside
  // it that say what is happening. It goes there without the jump that focus makes to the middle
  // of the screen, and the words are brought into view by as little as it takes, as the control was.
  const endingNote = useRef<HTMLParagraphElement | null>(null)
  const startControl = useRef<HTMLButtonElement | null>(null)
  const wasEnding = useRef(false)
  useEffect(() => {
    if (waiting && ending && !wasEnding.current) {
      endingNote.current?.focus({ preventScroll: true })
      endingNote.current?.scrollIntoView({ block: 'nearest' })
    }
    wasEnding.current = waiting && ending
  }, [ending, waiting])
  // The rule that holds whatever order the start's state changes in: the control and the words of
  // a start in flight are never left holding focus when they go. Where focus is on one of them is
  // read from the focus itself, and cleared when the person moves it elsewhere; when the element
  // that holds it is no longer on the screen, focus goes to what is there to take it: the control
  // that gives the start up if it is back (a stop that was refused), the control that starts
  // again, or the heading while that is not to be pressed. Never to the page.
  const inFlight = useRef<HTMLElement | null>(null)
  const remember = (event: React.FocusEvent) => {
    const target = event.target as HTMLElement
    inFlight.current = target === end.current || target === endingNote.current ? target : null
  }
  const forget = (event: React.FocusEvent) => {
    // A window that loses focus blurs the element that holds it in the page, with no element to
    // take it, and the page no longer has focus. That is not the person moving focus on the page:
    // the record is kept, and focus is repaired if the element goes meanwhile. (An element that
    // React takes away is not blurred through here: React does not dispatch events while it
    // removes.)
    if (event.target === inFlight.current && (event.relatedTarget !== null || document.hasFocus())) {
      inFlight.current = null
    }
  }
  useLayoutEffect(() => {
    const lost = inFlight.current
    if (lost === null || lost.isConnected) return
    inFlight.current = null
    const to = [end.current, startControl.current, heading.current].find(
      (candidate) => candidate !== null && !(candidate instanceof HTMLButtonElement && candidate.disabled)
    )
    to?.focus({ preventScroll: true })
    if (to instanceof HTMLButtonElement) to.scrollIntoView({ block: 'nearest' })
  })
  const terms = choice.managed
  const seconds = terms ? requestedSeconds(terms) : null
  const startable = terms !== null && terms.enabled && seconds !== null

  return (
    <section
      className="kr-voice"
      aria-labelledby={`${id}-heading`}
      onFocus={remember}
      onBlur={forget}
    >
      <h1 id={`${id}-heading`} className="kr-voice__title" ref={heading} tabIndex={-1}>
        Start a voice session
      </h1>

      {aftermath.length > 0 && (
        <div className="kr-voice__aftermath" role="status" aria-label="The last call">
          <ul className="kr-voice__list">
            {aftermath.map((line, index) => (
              <li key={`${String(index)}-${line}`}>{line}</li>
            ))}
          </ul>
        </div>
      )}

      {terms ? (
        <dl className="kr-voice__provider">
          <div>
            <dt>Voice model</dt>
            <dd>{terms.model}</dd>
          </div>
          <div>
            <dt>Brokered by</dt>
            <dd>{choice.brokerOrigin}</dd>
          </div>
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
        {/* What the grant permits and what this version carries out are different things, and the
            person reads the first list before they decide: so the second is said beside it. */}
        <p className="kr-voice__note">{NOT_ACTED_ON_WORDS}</p>
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
        <div className="kr-voice__begin">
          <button
            type="button"
            ref={startControl}
            className="kr-voice__start"
            onClick={onStart}
            disabled={busy}
            aria-describedby={`${id}-cost-rate ${id}-cost-limits`}
          >
            {busy ? 'Starting…' : choice.previousRate ? 'Start at the new rate' : 'Start voice session'}
          </button>
          {waiting && (
            <button
              type="button"
              ref={end}
              className="kr-voice__control kr-voice__control--end"
              onClick={onEnd}
              disabled={ending}
            >
              {ending ? 'Ending…' : 'End the call'}
            </button>
          )}
        </div>
      )}
      {waiting && ending && (
        <p className="kr-voice__note" role="status" ref={endingNote} tabIndex={-1}>
          {ENDING_WORDS}
        </p>
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
  readonly currentTurn: CurrentTurn | null
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
  const [confirmingCancel, setConfirmingCancel] = useState<CurrentTurn | null>(null)
  const [turnWhenAsked, setTurnWhenAsked] = useState(currentTurn)

  if (!sameTurn(turnWhenAsked, currentTurn)) {
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
    actions.cancelTask(confirmingCancel)
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
        <p className="kr-voice__note">{NOT_ACTED_ON_WORDS}</p>
        {call.delegations.length === 0 ? (
          <p className="kr-voice__note">Nothing yet.</p>
        ) : (
          <ul className="kr-voice__list">
            {call.delegations.map((delegation) => (
              <DelegationRow key={delegation.delegationId} delegation={delegation} />
            ))}
          </ul>
        )}
        {admitted > 0 && call.admissionMeans !== '' && (
          <p className="kr-voice__note">{call.admissionMeans}</p>
        )}
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

/** One delegation the voice announced: this version did nothing about it, and the row says so. */
function DelegationRow({ delegation }: { readonly delegation: Delegation }): React.ReactElement {
  return (
    <li className="kr-voice__delegation">
      <span className="kr-voice__kind">
        {delegation.offsetMs === null
          ? 'Asked earlier, at a time this device was not told'
          : `Asked ${(delegation.offsetMs / 1000).toFixed(1)} seconds in`}
      </span>
      <span className="kr-voice__summary">
        {delegation.told
          ? 'Not done. The voice was told so.'
          : 'Not done. The voice has not been told yet.'}
      </span>
    </li>
  )
}
