import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'

import { VoiceSurface, type VoiceSurfaceActions } from '../../src/voice/VoiceSurface'
import type { ProviderChoice, RunningCall } from '../../src/voice/model'

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
      { kind: 'session_description', summary: 'Building the release', tokens: 120 },
      { kind: 'working_directory', summary: '~/work/kalareach', tokens: 20 }
    ],
    withheld: [
      { kind: 'file_contents', reason: 'not selected' },
      { kind: 'terminal_scrollback', reason: 'not selected' }
    ],
    tokenCap: 8000,
    sessions: ['s-1'],
    permits: ['navigate sessions', 'ask for status', 'brief you', 'compose a prompt'],
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
    delegations: [],
    requests: [],
    firstAudioMs: 410,
    ...over
  }
}

function actions(): VoiceSurfaceActions {
  return {
    start: vi.fn(),
    setMicrophoneMuted: vi.fn(),
    stopPlayback: vi.fn(),
    hangUp: vi.fn(),
    cancelTask: vi.fn()
  }
}

describe('before voice starts', () => {
  // KR-REQ-15.19: the provider and the selected context scope are shown before voice starts.
  it('names the provider and what would be sent, above the control that starts it', () => {
    render(<VoiceSurface choice={choice()} call={null} currentTurn={null} actions={actions()} />)

    expect(screen.getByText('gpt-live-1')).toBeInTheDocument()
    expect(screen.getByText('https://reach.kala.to')).toBeInTheDocument()

    const scope = screen.getByRole('region', { name: 'What will be sent' })
    expect(within(scope).getByText('session description')).toBeInTheDocument()
    expect(within(scope).getByText('working directory')).toBeInTheDocument()
    expect(within(scope).getByText(/8,000 tokens this host allows/)).toBeInTheDocument()

    // What is not sent, beside what is.
    expect(within(scope).getByText('file contents')).toBeInTheDocument()
    expect(within(scope).getByText('terminal scrollback')).toBeInTheDocument()
  })

  // KR-REQ-15.09: the managed content access is disclosed in the provider choice.
  it('states the managed content access in the service’s own words', () => {
    render(<VoiceSurface choice={choice()} call={null} currentTurn={null} actions={actions()} />)
    const access = screen.getByRole('region', { name: 'What this gives access to' })
    for (const line of DISCLOSURE) {
      expect(within(access).getByText(line)).toBeInTheDocument()
    }
  })

  it('refuses to start a call whose context is over the host’s cap', () => {
    render(
      <VoiceSurface choice={choice({ tokenCap: 100 })} call={null} currentTurn={null} actions={actions()} />
    )
    expect(screen.getByRole('button', { name: 'Start voice session' })).toBeDisabled()
  })

  it('says a model statement is not a confirmation, before any audio is captured', () => {
    render(<VoiceSurface choice={choice()} call={null} currentTurn={null} actions={actions()} />)
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
      <VoiceSurface choice={choice()} call={call({ capture })} currentTurn={null} actions={actions()} />
    )
    expect(screen.getByRole('status')).toHaveTextContent(display)
    expect(screen.getByText(/can authorise an action/)).toBeInTheDocument()
  })

  it('shows no refusal while the microphone is carrying the person’s voice', () => {
    render(<VoiceSurface choice={choice()} call={call()} currentTurn={null} actions={actions()} />)
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
        actions={acted}
      />
    )
    await person.click(screen.getByRole('button', { name: 'Mute microphone' }))
    await person.click(screen.getByRole('button', { name: 'Stop the voice' }))
    await person.click(screen.getByRole('button', { name: 'End session' }))
    expect(acted.setMicrophoneMuted).toHaveBeenCalledWith(true)
    expect(acted.stopPlayback).toHaveBeenCalledTimes(1)
    expect(acted.hangUp).toHaveBeenCalledTimes(1)

    expect(screen.getByRole('button', { name: 'Cancel the current turn' })).toBeDisabled()
  })

  // KR-REQ-15.17: an append acknowledgement is shown as admission, never as execution.
  it('says what an acknowledgement does not establish', () => {
    render(
      <VoiceSurface
        choice={choice()}
        call={call({
          requests: [{ id: 'r-1', command: 'commentary', outcome: 'admitted' }],
          delegations: [
            { delegationId: 'd-1', offsetMs: 1200, state: 'submitted', detail: 'Read session 1' }
          ]
        })}
        currentTurn={null}
        actions={actions()}
      />
    )
    expect(screen.getByText(/not evidence that anything ran on a host/)).toBeInTheDocument()
    expect(screen.queryByText(/\bexecuted\b/i)).not.toBeInTheDocument()
  })

  // Section 13 line 879: every control this screen adds meets the platform's target minimum and
  // carries a name a screen reader can speak.
  it('gives every control an accessible name', () => {
    render(<VoiceSurface choice={choice()} call={call()} currentTurn={null} actions={actions()} />)
    for (const control of screen.getAllByRole('button')) {
      expect(control).toHaveAccessibleName()
    }
  })
})
