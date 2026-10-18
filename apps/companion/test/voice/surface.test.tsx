import { fireEvent, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'

import {
  VoiceSurface,
  type CurrentTurn,
  type VoiceSurfaceActions
} from '../../src/voice/VoiceSurface'
import { CONTEXT_OUTCOMES, type ProviderChoice, type RunningCall } from '../../src/voice/model'

/** What the host says an append acknowledgement does not establish. */
const ADMISSION_MEANS =
  'The model received this context. It is not evidence that a host action ran or that audio was played; host action receipts are the authority for that.'

/** The deployed service's own disclosure list, as the host carries it through. */
const DISCLOSURE = [
  'Audio travels directly between this device and the provider, not through this service.',
  'The provider and this service can process the speech and the context the host selects.',
  "This service's own channel to the provider still receives transcripts and copies of the audio.",
  'Selected context and host results are sent as bounded requests.',
  'A statement from the model that you confirmed something is not a confirmation.'
]

/** The managed service's terms, as the host carries them through. */
const TERMS: NonNullable<ProviderChoice['managed']> = {
  enabled: true,
  model: 'gpt-live-1',
  disclosure: DISCLOSURE,
  admission_note: ADMISSION_MEANS,
  delegation_note: 'A provider delegation identifier is correlation data.',
  alternatives: [
    'The coding agent already running on the host, reached by typing rather than speaking.'
  ],
  rate: { version: '2026-09-a', minor_units_per_second: '2', minimum_seconds: 15, currency: 'usd' },
  maximum_session_seconds: 1800,
  minimum_request_seconds: 60,
  heartbeat_seconds: 20,
  context_bytes: 500
}

function choice(over: Partial<ProviderChoice> = {}): ProviderChoice {
  return {
    brokerOrigin: 'https://reach.kala.to',
    prepared: 'scope-1',
    managed: TERMS,
    unavailable: null,
    previousRate: null,
    context: [
      { kind: 'the session', summary: 'its description, working directory and the last 20 messages' }
    ],
    withheld: [
      { kind: 'file_contents', summary: 'the contents of files', reason: 'not selected' },
      { kind: 'terminal_scrollback', summary: 'raw terminal scrollback', reason: 'not selected' }
    ],
    tokenCap: 8000,
    messageCount: 20,
    sessions: ['s-1'],
    sessionNames: { 's-1': 'Session 3' },
    permits: ['navigate sessions', 'ask for status', 'brief you', 'compose a prompt'],
    needsUnlockedScreen: false,
    ...over
  }
}

function call(over: Partial<RunningCall> = {}): RunningCall {
  return {
    voiceSessionId: 'vs-1',
    callId: 'call-1',
    sessions: ['s-1'],
    model: 'gpt-live-1',
    closesAtMs: 1_800_000,
    capture: 'capturing',
    playing: true,
    brokerReachable: true,
    hostReachable: true,
    callHost: 'reachable',
    delegations: [],
    requests: [],
    admissionMeans: ADMISSION_MEANS,
    ...over
  }
}

/** A turn of session s-1's agent, at binding revision 3 unless a test says otherwise. */
function turn(turnId: string, bindingRevision = '3'): CurrentTurn {
  return { sessionId: 's-1', instanceId: 'i-1', bindingRevision, turnId }
}

function actions(): VoiceSurfaceActions {
  return {
    start: vi.fn(),
    setMicrophoneMuted: vi.fn(),
    stopPlayback: vi.fn(),
    hangUp: vi.fn(),
    endSetup: vi.fn(),
    cancelTask: vi.fn(),
    readSelection: vi.fn()
  }
}

describe('before voice starts', () => {
  // KR-REQ-15.19: the provider and the selected context scope are shown before voice starts.
  it('names the provider and what would be sent, above the control that starts it', () => {
    render(<VoiceSurface choice={choice()} call={null} currentTurn={null} busy={false}
        notice={null}
        actions={actions()} />)

    expect(screen.getByText('gpt-live-1')).toBeInTheDocument()
    expect(screen.getByText('https://reach.kala.to')).toBeInTheDocument()

    const scope = screen.getByRole('region', { name: 'What will be sent' })
    expect(within(scope).getByText('the session')).toBeInTheDocument()
    expect(within(scope).getByText(/at most 8,000 tokens/)).toBeInTheDocument()

    // What is not sent, beside what is.
    expect(within(scope).getByText('the contents of files')).toBeInTheDocument()
    expect(within(scope).getByText('raw terminal scrollback')).toBeInTheDocument()
  })

  // KR-REQ-15.09: the managed content access is disclosed in the provider choice.
  it('states the managed content access in the service’s own words', () => {
    render(<VoiceSurface choice={choice()} call={null} currentTurn={null} busy={false}
        notice={null}
        actions={actions()} />)
    const access = screen.getByRole('region', { name: 'What this gives access to' })
    for (const line of DISCLOSURE) {
      expect(within(access).getByText(line)).toBeInTheDocument()
    }
  })

  // KR-REQ-15.19: the cap is the host's, and so is a refusal to start against it. The screen shows
  // what the host said rather than deciding for itself that a call cannot be made.
  it('shows the host’s own refusal instead of deciding one', () => {
    render(
      <VoiceSurface
        choice={choice()}
        call={null}
        currentTurn={null}
        busy={false}
        notice="The selected context is over this host's cap of 100 tokens."
        actions={actions()}
      />
    )
    expect(screen.getByText(/over this host's cap of 100 tokens/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Start voice session' })).toBeEnabled()
  })

  // One press is one call. A second press while the first is in flight would ask the service for a
  // second metered provider session.
  it('takes the start control away while a start is in flight', () => {
    render(
      <VoiceSurface
        choice={choice()}
        call={null}
        currentTurn={null}
        busy={true}
        notice={null}
        actions={actions()}
      />
    )
    expect(screen.getByRole('button', { name: 'Starting…' })).toBeDisabled()
  })

  // A start waits for the host for as long as the host takes, up to a minute and a half. The person
  // who pressed it can end it from the same place, and the control to end it is not there before
  // there is anything to end.
  it('offers an end beside the start control while a start is in flight, and not before', async () => {
    const person = userEvent.setup()
    const acted = actions()
    const { rerender } = render(
      <VoiceSurface choice={choice()} call={null} currentTurn={null} busy={false} notice={null} actions={acted} />
    )
    expect(screen.queryByRole('button', { name: 'End the call' })).not.toBeInTheDocument()

    // Busy with what the host answered, which is a call or nothing: nothing is left to give up.
    rerender(<VoiceSurface choice={choice()} call={null} currentTurn={null} busy notice={null} actions={acted} />)
    expect(screen.queryByRole('button', { name: 'End the call' })).not.toBeInTheDocument()

    rerender(
      <VoiceSurface choice={choice()} call={null} currentTurn={null} busy waiting notice={null} actions={acted} />
    )
    await person.click(screen.getByRole('button', { name: 'End the call' }))

    expect(acted.endSetup).toHaveBeenCalledTimes(1)
    expect(acted.start).not.toHaveBeenCalled()
    // The control that was pressed is not where focus stays: it is disabled next and gone after.
    // The screen is told the end has begun, and focus goes to the words that say so.
    rerender(
      <VoiceSurface
        choice={choice()}
        call={null}
        currentTurn={null}
        busy
        waiting
        ending
        notice={null}
        actions={acted}
      />
    )
    expect(screen.getByText(/is ending its call/)).toHaveFocus()

    // The start is over: the words are gone, and focus is on the control that starts again.
    rerender(
      <VoiceSurface choice={choice()} call={null} currentTurn={null} busy={false} notice={null} actions={acted} />
    )
    expect(screen.getByRole('button', { name: 'Start voice session' })).toHaveFocus()
  })

  // Once the end has begun there is nothing more to ask: the control says so and cannot be pressed
  // a second time.
  it('says the end has begun and takes the control away once it has', () => {
    render(
      <VoiceSurface
        choice={choice()}
        call={null}
        currentTurn={null}
        busy
        waiting
        ending
        notice={null}
        actions={actions()}
      />
    )
    expect(screen.getByRole('button', { name: 'Ending…' })).toBeDisabled()
    expect(screen.queryByRole('button', { name: 'End the call' })).not.toBeInTheDocument()
    expect(screen.getByText(/is ending its call/)).toBeInTheDocument()
  })

  // The rule behind the focus of a start in flight: whatever order its state changes in, the
  // control and the words of the start are never left holding focus when they go, and the person's
  // own move of focus is left alone.
  describe('focus while a start is in flight', () => {
    const screenWith = (
      state: { busy: boolean; waiting: boolean; ending: boolean },
      acted = actions()
    ): React.ReactElement => (
      <VoiceSurface
        choice={choice()}
        call={null}
        currentTurn={null}
        busy={state.busy}
        waiting={state.waiting}
        ending={state.ending}
        notice={null}
        actions={acted}
      />
    )
    const IN_FLIGHT = { busy: true, waiting: true, ending: false }
    const ENDING = { busy: true, waiting: true, ending: true }
    const REFUSED = IN_FLIGHT
    const ANSWERED_WHILE_ENDING = { busy: true, waiting: false, ending: true }
    const OVER = { busy: false, waiting: false, ending: false }

    it('goes from the control the person reached to the start control when the start is over', async () => {
      const person = userEvent.setup()
      const { rerender } = render(screenWith(IN_FLIGHT))
      await person.tab()
      expect(screen.getByRole('button', { name: 'End the call' })).toHaveFocus()

      rerender(screenWith(OVER))

      expect(screen.getByRole('button', { name: 'Start voice session' })).toHaveFocus()
    })

    it('goes back to the control after a refused stop, and to the start control when the start is over', () => {
      const { rerender } = render(screenWith(IN_FLIGHT))
      screen.getByRole('button', { name: 'End the call' }).focus()
      rerender(screenWith(ENDING))
      expect(screen.getByText(/is ending its call/)).toHaveFocus()

      rerender(screenWith(REFUSED))
      expect(screen.getByRole('button', { name: 'End the call' })).toHaveFocus()

      rerender(screenWith(OVER))
      expect(screen.getByRole('button', { name: 'Start voice session' })).toHaveFocus()
    })

    it('stays on the screen while what a call would be is read again', () => {
      const { rerender } = render(screenWith(IN_FLIGHT))
      screen.getByRole('button', { name: 'End the call' }).focus()
      rerender(screenWith(ENDING))
      expect(screen.getByText(/is ending its call/)).toHaveFocus()

      // The host has answered while the end ran, and the start control is not yet to be pressed.
      rerender(screenWith(ANSWERED_WHILE_ENDING))
      const heading = screen.getByRole('heading', { name: 'Start a voice session' })
      expect(heading).toHaveFocus()

      rerender(screenWith(OVER))
      expect(heading).toHaveFocus()
    })

    it('leaves focus on a control outside the screen that the person moved it to', () => {
      const { rerender } = render(
        <>
          <button type="button">Elsewhere</button>
          {screenWith(IN_FLIGHT)}
        </>
      )
      screen.getByRole('button', { name: 'End the call' }).focus()
      rerender(
        <>
          <button type="button">Elsewhere</button>
          {screenWith(ENDING)}
        </>
      )
      expect(screen.getByText(/is ending its call/)).toHaveFocus()
      // The person moves focus out of the screen, to another control of the page.
      const elsewhere = screen.getByRole('button', { name: 'Elsewhere' })
      elsewhere.focus()

      rerender(
        <>
          <button type="button">Elsewhere</button>
          {screenWith(OVER)}
        </>
      )

      expect(elsewhere).toHaveFocus()
    })

    it('repairs focus when the window loses focus while the end runs and the start is over before it is back', () => {
      const { rerender } = render(screenWith(IN_FLIGHT))
      screen.getByRole('button', { name: 'End the call' }).focus()
      rerender(screenWith(ENDING))
      const said = screen.getByText(/is ending its call/)
      expect(said).toHaveFocus()
      // The window goes to another application: the page's focused element is blurred, and the page
      // itself no longer has focus. That is not the person moving focus on the page.
      const hasFocus = vi.spyOn(document, 'hasFocus').mockReturnValue(false)
      fireEvent.focusOut(said)
      hasFocus.mockRestore()

      rerender(screenWith(OVER))

      expect(screen.getByRole('button', { name: 'Start voice session' })).toHaveFocus()
    })

    it('leaves focus where the person put it', () => {
      const { rerender } = render(screenWith(IN_FLIGHT))
      screen.getByRole('button', { name: 'End the call' }).focus()
      rerender(screenWith(ENDING))
      expect(screen.getByText(/is ending its call/)).toHaveFocus()
      // The person moves focus to the heading themselves.
      const heading = screen.getByRole('heading', { name: 'Start a voice session' })
      heading.focus()

      rerender(screenWith(OVER))

      expect(heading).toHaveFocus()
    })
  })

  it('says a model statement is not a confirmation once, in the service’s words', () => {
    render(<VoiceSurface choice={choice()} call={null} currentTurn={null} busy={false}
        notice={null}
        actions={actions()} />)
    // Once: the service states it in its disclosure, and a second wording on this screen would be
    // a second thing to keep true. What the screen says beside the grant is the host's own rule.
    expect(screen.getAllByText(/is not a confirmation/)).toHaveLength(1)
    const access = screen.getByRole('region', { name: 'What this gives access to' })
    expect(within(access).getByText(/is not a confirmation/)).toBeInTheDocument()
    const permits = screen.getByRole('region', {
      name: 'What speaking will be allowed to do'
    })
    expect(within(permits).getByText(/refuses anything not listed/)).toBeInTheDocument()
  })

  // KR-REQ-15.19: the sessions a call would reach are shown, by the host's own names where it
  // gave them, and by identifier where it did not.
  it('shows the sessions the call would reach', () => {
    render(
      <VoiceSurface
        choice={choice({ sessions: ['s-1', 's-2'], sessionNames: { 's-1': 'Session 3' } })}
        call={null}
        currentTurn={null}
        busy={false}
        notice={null}
        actions={actions()}
      />
    )
    const sessions = screen.getByRole('region', { name: 'Sessions this call can reach' })
    expect(within(sessions).getByText('Session 3')).toBeInTheDocument()
    expect(within(sessions).getByText('s-2')).toBeInTheDocument()
  })

  // KR-REQ-15.19: the rate is shown before a call, directly above the control that accepts it.
  it('shows what a call costs above the control that starts it', () => {
    render(<VoiceSurface choice={choice()} call={null} currentTurn={null} busy={false}
        notice={null}
        actions={actions()} />)
    const cost = screen.getByRole('region', { name: 'What it costs' })
    expect(within(cost).getByText(/0\.02 a second/)).toBeInTheDocument()
    expect(within(cost).getByText(/1\.20 a minute/)).toBeInTheDocument()
    expect(within(cost).getByText(/at least 15 seconds/)).toBeInTheDocument()
    expect(within(cost).getByText(/up to 30 minutes, so it can cost at most \S*36\.00/)).toBeInTheDocument()

    const start = screen.getByRole('button', { name: 'Start voice session' })
    // The rate sits before the start in reading order, so it is read before it is accepted, and
    // the control itself is described by it for anyone who reaches the control first.
    expect(cost.compareDocumentPosition(start) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
    expect(start).toHaveAccessibleDescription(/0\.02 a second.*at least 15 seconds/)
  })

  // KR-REQ-15.19: without the service's terms there is nothing to accept, so there is no start,
  // and the host's reason is what the person reads instead.
  it('offers no start without the service’s terms, and says why', () => {
    render(
      <VoiceSurface
        choice={choice({
          managed: null,
          unavailable: 'This host could not read the managed service’s terms.'
        })}
        call={null}
        currentTurn={null}
        busy={false}
        notice={null}
        actions={actions()}
      />
    )
    expect(screen.getByText('This host could not read the managed service’s terms.')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Start/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('region', { name: 'What it costs' })).not.toBeInTheDocument()
    expect(screen.queryByRole('region', { name: 'What this gives access to' })).not.toBeInTheDocument()
    // The scope is still the host's to state.
    expect(screen.getByRole('region', { name: 'What will be sent' })).toBeInTheDocument()
  })

  // The operator's circuit breaker: no start, and what still works.
  it('offers no start while managed voice is closed, and lists what still works', () => {
    render(
      <VoiceSurface
        choice={choice({ managed: { ...TERMS, enabled: false } })}
        call={null}
        currentTurn={null}
        busy={false}
        notice={null}
        actions={actions()}
      />
    )
    const closed = screen.getByRole('region', { name: 'Managed voice is closed at the moment' })
    expect(within(closed).getByText(TERMS.alternatives[0])).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Start/ })).not.toBeInTheDocument()
  })

  // A start refused because the rate moved on: the new rate is shown with the old one beside it,
  // and starting again is a press that names what it accepts.
  it('shows a changed rate beside the one read before, and asks again to start', () => {
    render(
      <VoiceSurface
        choice={choice({
          managed: {
            ...TERMS,
            rate: { ...TERMS.rate, version: '2026-10-b', minor_units_per_second: '3' }
          },
          previousRate: TERMS.rate
        })}
        call={null}
        currentTurn={null}
        busy={false}
        notice={null}
        actions={actions()}
      />
    )
    const cost = screen.getByRole('region', { name: 'What it costs' })
    // The announcement carries the new rate as well as the old, so what is heard is what would now
    // be accepted.
    expect(within(cost).getByRole('status')).toHaveTextContent(
      /The rate changed after you read it\. It is now \S*0\.03 a second, and was \S*0\.02\. Nothing was started or charged\./
    )
    const accept = screen.getByRole('button', { name: 'Start at the new rate' })
    expect(accept).toBeEnabled()
    expect(accept).toHaveAccessibleDescription(/0\.03 a second/)
  })
})

describe('while a call is running', () => {
  // KR-REQ-15.36, KR-ACC-014: muted or unavailable capture is displayed, and the refusal is shown.
  it.each([
    ['muted_by_person' as const, 'Microphone muted'],
    ['unavailable' as const, 'No microphone available'],
    ['interrupted' as const, 'Microphone taken by another call'],
    ['suspended_by_system' as const, 'Microphone paused by the system']
  ])('shows %s and refuses to treat unheard speech as authority', (capture, display) => {
    render(
      <VoiceSurface choice={choice()} call={call({ capture })} currentTurn={null} busy={false}
        notice={null}
        actions={actions()} />
    )
    expect(screen.getByRole('status')).toHaveTextContent(display)
    expect(screen.getByText(/can authorise an action/)).toBeInTheDocument()
  })

  it('shows no refusal while the microphone is carrying the person’s voice', () => {
    render(<VoiceSurface choice={choice()} call={call()} currentTurn={null} busy={false}
        notice={null}
        actions={actions()} />)
    expect(screen.queryByText(/can authorise an action/)).not.toBeInTheDocument()
  })

  // KR-REQ-15.22: stopping playback does not reach the task-cancellation path.
  it('stops the voice without cancelling anything', async () => {
    const acted = actions()
    const person = userEvent.setup()
    render(
      <VoiceSurface
        choice={choice()}
        call={call()}
        currentTurn={turn('t-9')}
        busy={false}
        notice={null}
        actions={acted}
      />
    )
    await person.click(screen.getByRole('button', { name: 'Stop the voice' }))
    expect(acted.stopPlayback).toHaveBeenCalledTimes(1)
    expect(acted.cancelTask).not.toHaveBeenCalled()
  })

  // KR-REQ-15.22: cancellation is a separate, confirmed control that names the current turn.
  it('cancels a turn only after a deliberate second step, and names the turn', async () => {
    const acted = actions()
    const person = userEvent.setup()
    render(
      <VoiceSurface
        choice={choice()}
        call={call()}
        currentTurn={turn('t-9')}
        busy={false}
        notice={null}
        actions={acted}
      />
    )
    await person.click(screen.getByRole('button', { name: 'Cancel the current turn' }))
    expect(acted.cancelTask).not.toHaveBeenCalled()

    await person.click(screen.getByRole('button', { name: 'Cancel this turn' }))
    expect(acted.cancelTask).toHaveBeenCalledWith(turn('t-9'))
    expect(acted.stopPlayback).not.toHaveBeenCalled()
  })

  // KR-REQ-15.17: local mute and closure survive the broker failing.
  it('keeps mute, stopping the voice and ending the session when the broker is gone', async () => {
    const acted = actions()
    const person = userEvent.setup()
    render(
      <VoiceSurface
        choice={choice()}
        call={call({ brokerReachable: false })}
        currentTurn={turn('t-9')}
        busy={false}
        notice={null}
        actions={acted}
      />
    )
    await person.click(screen.getByRole('button', { name: 'Mute microphone' }))
    await person.click(screen.getByRole('button', { name: 'Stop the voice' }))
    await person.click(screen.getByRole('button', { name: 'End session' }))
    expect(acted.setMicrophoneMuted).toHaveBeenCalledWith(true)
    expect(acted.stopPlayback).toHaveBeenCalledTimes(1)
    expect(acted.hangUp).toHaveBeenCalledTimes(1)

    // The cancellation goes to the host over a different connection, so the voice service being
    // gone does not take it away.
    expect(screen.getByRole('button', { name: 'Cancel the current turn' })).toBeEnabled()
  })

  // KR-REQ-15.22: the cancellation path needs the host, and only the host.
  it('refuses a cancellation when the host is the connection that is gone', () => {
    render(
      <VoiceSurface
        choice={choice()}
        call={call({ hostReachable: false })}
        currentTurn={turn('t-9')}
        busy={false}
        notice={null}
        actions={actions()}
      />
    )
    expect(screen.getByRole('button', { name: 'Cancel the current turn' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Mute microphone' })).toBeEnabled()
    expect(screen.getByRole('button', { name: 'End session' })).toBeEnabled()
  })

  // KR-REQ-15.22, KR-ACC-014: a confirmation names one turn. If the host moves on while the
  // question is on screen, the answer must not land on the turn that replaced it.
  it('voids an open confirmation when the host moves to another turn', async () => {
    const acted = actions()
    const person = userEvent.setup()
    const { rerender } = render(
      <VoiceSurface
        choice={choice()}
        call={call()}
        currentTurn={turn('t-9')}
        busy={false}
        notice={null}
        actions={acted}
      />
    )
    await person.click(screen.getByRole('button', { name: 'Cancel the current turn' }))
    expect(screen.getByRole('button', { name: 'Cancel this turn' })).toBeInTheDocument()

    rerender(
      <VoiceSurface
        choice={choice()}
        call={call()}
        currentTurn={turn('t-10')}
        busy={false}
        notice={null}
        actions={acted}
      />
    )
    expect(screen.queryByRole('button', { name: 'Cancel this turn' })).not.toBeInTheDocument()
    expect(acted.cancelTask).not.toHaveBeenCalled()
  })

  // KR-REQ-15.22: a question the host moved past is thrown away, not hidden. Returning to the
  // same turn must not bring back an answer nobody gave.
  it.each([
    ['another turn', turn('t-10')],
    ['the same turn at a newer binding', turn('t-9', '4')],
    ['no turn at all', null]
  ])('does not revive a confirmation after the host moves to %s', async (_name, moved) => {
    const acted = actions()
    const person = userEvent.setup()
    const view = (shown: CurrentTurn | null) => (
      <VoiceSurface choice={choice()} call={call()} currentTurn={shown} busy={false}
        notice={null}
        actions={acted} />
    )
    const { rerender } = render(view(turn('t-9')))
    await person.click(screen.getByRole('button', { name: 'Cancel the current turn' }))
    expect(screen.getByRole('button', { name: 'Cancel this turn' })).toBeInTheDocument()

    rerender(view(moved))
    rerender(view(turn('t-9')))

    expect(screen.queryByRole('button', { name: 'Cancel this turn' })).not.toBeInTheDocument()
    expect(acted.cancelTask).not.toHaveBeenCalled()
  })

  // KR-REQ-15.22: the host can go while the question is on screen. A cancellation that cannot be
  // delivered is refused rather than reported as sent.
  it('refuses to send a confirmed cancellation once the host has gone', async () => {
    const acted = actions()
    const person = userEvent.setup()
    const running = turn('t-9')
    const view = (reachable: boolean) => (
      <VoiceSurface
        choice={choice()}
        call={call({ hostReachable: reachable })}
        currentTurn={running}
        busy={false}
        notice={null}
        actions={acted}
      />
    )
    const { rerender } = render(view(true))
    await person.click(screen.getByRole('button', { name: 'Cancel the current turn' }))

    rerender(view(false))
    const confirm = screen.getByRole('button', { name: 'Cancel this turn' })
    expect(confirm).toBeDisabled()
    await person.click(confirm)
    expect(acted.cancelTask).not.toHaveBeenCalled()
  })

  // Section 13 line 879: focus follows the question and returns to the control that asked it.
  it('moves focus into the confirmation and back again', async () => {
    const person = userEvent.setup()
    render(
      <VoiceSurface
        choice={choice()}
        call={call()}
        currentTurn={turn('t-9')}
        busy={false}
        notice={null}
        actions={actions()}
      />
    )
    await person.click(screen.getByRole('button', { name: 'Cancel the current turn' }))
    expect(screen.getByRole('button', { name: 'Cancel this turn' })).toHaveFocus()

    await person.click(screen.getByRole('button', { name: 'Keep it running' }))
    expect(screen.getByRole('button', { name: 'Cancel the current turn' })).toHaveFocus()
  })

  // KR-REQ-15.17: an append acknowledgement is shown as admission, never as execution. Every
  // outcome the model defines is rendered, walked from the list the type is read off, so an
  // outcome added later that reads as execution fails here rather than reaching a person.
  it.each(CONTEXT_OUTCOMES.map((outcome) => [outcome] as const))(
    'never presents the %s outcome as work a host did',
    (outcome) => {
      render(
        <VoiceSurface
          choice={choice()}
          call={call({
            requests: [{ id: 'r-1', command: 'commentary', outcome }],
            delegations: [{ delegationId: 'd-1', offsetMs: 1200, told: true }]
          })}
          currentTurn={null}
          busy={false}
        notice={null}
        actions={actions()}
        />
      )
      expect(screen.queryByText(/\bexecuted\b|\bcompleted\b|\bsucceeded\b/i)).not.toBeInTheDocument()
      if (outcome === 'admitted') {
        expect(screen.getByText(ADMISSION_MEANS)).toBeInTheDocument()
      } else {
        expect(screen.queryByText(ADMISSION_MEANS)).not.toBeInTheDocument()
      }
    }
  )

  // A delegation the voice service listed when the control attached has no offset, and is not said
  // to have been asked at the start of the call.
  it('does not place a delegation in the call when the service gave no offset', () => {
    render(
      <VoiceSurface
        choice={choice()}
        call={call({
          delegations: [
            { delegationId: 'd-0', offsetMs: null, told: true },
            { delegationId: 'd-1', offsetMs: 1200, told: true }
          ]
        })}
        currentTurn={null}
        busy={false}
        notice={null}
        actions={actions()}
      />
    )
    expect(screen.getByText('Asked earlier, at a time this device was not told')).toBeInTheDocument()
    expect(screen.getByText('Asked 1.2 seconds in')).toBeInTheDocument()
    expect(screen.queryByText('Asked 0.0 seconds in')).not.toBeInTheDocument()
  })

  // The device is making a call that has no descriptor to name: the screen offers no second start,
  // which the device would turn away, and offers the one thing that can be done.
  it('offers an end and no start while the device is setting a call up', async () => {
    const person = userEvent.setup()
    const acted = actions()
    render(
      <VoiceSurface
        choice={choice()}
        call={null}
        currentTurn={null}
        busy={false}
        notice={null}
        settingUp
        actions={acted}
      />
    )
    expect(screen.queryByRole('button', { name: 'Start voice session' })).not.toBeInTheDocument()

    await person.click(screen.getByRole('button', { name: 'End the call' }))

    expect(acted.endSetup).toHaveBeenCalledTimes(1)
    expect(acted.hangUp).not.toHaveBeenCalled()
  })

  // Once the end has begun there is nothing more to ask of the device: the screen says it is ending
  // and offers nothing to press, and says nothing of the microphone, which it cannot know.
  it('offers nothing to press while the device is ending its call', () => {
    render(
      <VoiceSurface
        choice={choice()}
        call={null}
        currentTurn={null}
        busy={false}
        notice={null}
        settingUp
        ending
        actions={actions()}
      />
    )
    expect(screen.getByRole('heading', { name: 'Ending a voice session' })).toBeInTheDocument()
    expect(screen.queryByRole('button')).not.toBeInTheDocument()
    expect(screen.queryByText(/Nothing is listening/)).not.toBeInTheDocument()
  })

  // Section 13 line 879: every control this screen adds meets the platform's target minimum and
  // carries a name a screen reader can speak.
  it('gives every control an accessible name', () => {
    render(<VoiceSurface choice={choice()} call={call()} currentTurn={null} busy={false}
        notice={null}
        actions={actions()} />)
    for (const control of screen.getAllByRole('button')) {
      expect(control).toHaveAccessibleName()
    }
  })
})
