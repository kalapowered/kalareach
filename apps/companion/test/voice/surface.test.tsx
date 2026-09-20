import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'

import { VoiceSurface, type VoiceSurfaceActions } from '../../src/voice/VoiceSurface'
import type { ProviderChoice, RunningCall } from '../../src/voice/model'

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

function choice(over: Partial<ProviderChoice> = {}): ProviderChoice {
  return {
    model: 'gpt-live-1',
    brokerOrigin: 'https://reach.kala.to',
    disclosure: DISCLOSURE,
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
    permits: ['navigate sessions', 'ask for status', 'brief you', 'compose a prompt'],
    admissionMeans: ADMISSION_MEANS,
    ...over
  }
}

function call(over: Partial<RunningCall> = {}): RunningCall {
  return {
    voiceSessionId: 'vs-1',
    callId: 'call-1',
    model: 'gpt-live-1',
    closesAtMs: 1_800_000,
    capture: 'capturing',
    playing: true,
    brokerReachable: true,
    hostReachable: true,
    delegations: [],
    requests: [],
    firstAudioMs: null,
    admissionMeans: ADMISSION_MEANS,
    ...over
  }
}

function actions(): VoiceSurfaceActions {
  return {
    start: vi.fn(),
    setMicrophoneMuted: vi.fn(),
    stopPlayback: vi.fn(),
    hangUp: vi.fn(),
    cancelTask: vi.fn(),
    sendContext: vi.fn()
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

  it('says a model statement is not a confirmation, before any audio is captured', () => {
    render(<VoiceSurface choice={choice()} call={null} currentTurn={null} busy={false}
        notice={null}
        actions={actions()} />)
    // Said twice on purpose, and both are asserted: the service states it in its disclosure, and
    // the screen states it again beside what speaking will be allowed to do, which is where a
    // person is deciding.
    const permits = screen.getByRole('region', {
      name: 'What speaking will be allowed to do'
    })
    expect(within(permits).getByText(/is not a confirmation/)).toBeInTheDocument()
    const access = screen.getByRole('region', { name: 'What this gives access to' })
    expect(within(access).getByText(/is not a confirmation/)).toBeInTheDocument()
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
        currentTurn={{ sessionId: 's-1', turnId: 't-9' }}
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
        currentTurn={{ sessionId: 's-1', turnId: 't-9' }}
        busy={false}
        notice={null}
        actions={acted}
      />
    )
    await person.click(screen.getByRole('button', { name: 'Cancel the current turn' }))
    expect(acted.cancelTask).not.toHaveBeenCalled()

    await person.click(screen.getByRole('button', { name: 'Cancel this turn' }))
    expect(acted.cancelTask).toHaveBeenCalledWith('s-1', 't-9')
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
        currentTurn={{ sessionId: 's-1', turnId: 't-9' }}
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
        currentTurn={{ sessionId: 's-1', turnId: 't-9' }}
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
        currentTurn={{ sessionId: 's-1', turnId: 't-9' }}
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
        currentTurn={{ sessionId: 's-1', turnId: 't-10' }}
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
    ['another turn', { sessionId: 's-1', turnId: 't-10' }],
    ['no turn at all', null]
  ])('does not revive a confirmation after the host moves to %s', async (_name, moved) => {
    const acted = actions()
    const person = userEvent.setup()
    const view = (turn: { sessionId: string; turnId: string } | null) => (
      <VoiceSurface choice={choice()} call={call()} currentTurn={turn} busy={false}
        notice={null}
        actions={acted} />
    )
    const { rerender } = render(view({ sessionId: 's-1', turnId: 't-9' }))
    await person.click(screen.getByRole('button', { name: 'Cancel the current turn' }))
    expect(screen.getByRole('button', { name: 'Cancel this turn' })).toBeInTheDocument()

    rerender(view(moved))
    rerender(view({ sessionId: 's-1', turnId: 't-9' }))

    expect(screen.queryByRole('button', { name: 'Cancel this turn' })).not.toBeInTheDocument()
    expect(acted.cancelTask).not.toHaveBeenCalled()
  })

  // KR-REQ-15.22: the host can go while the question is on screen. A cancellation that cannot be
  // delivered is refused rather than reported as sent.
  it('refuses to send a confirmed cancellation once the host has gone', async () => {
    const acted = actions()
    const person = userEvent.setup()
    const turn = { sessionId: 's-1', turnId: 't-9' }
    const view = (reachable: boolean) => (
      <VoiceSurface
        choice={choice()}
        call={call({ hostReachable: reachable })}
        currentTurn={turn}
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
        currentTurn={{ sessionId: 's-1', turnId: 't-9' }}
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
  // outcome the model defines is rendered, so an outcome added later that reads as execution fails
  // here rather than reaching a person.
  it.each([['sent'], ['accepted'], ['admitted'], ['refused']] as const)(
    'never presents the %s outcome as work a host did',
    (outcome) => {
      render(
        <VoiceSurface
          choice={choice()}
          call={call({
            requests: [{ id: 'r-1', command: 'commentary', outcome }],
            delegations: [
              { delegationId: 'd-1', offsetMs: 1200, state: 'submitted', detail: 'Read session 1' }
            ]
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
