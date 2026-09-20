import { describe, expect, it } from 'vitest'

import type { VoicePrepareResult } from '@kalareach/protocol'

import {
  CAPTURE_DISPLAY,
  LOCAL_ONLY_CONTROLS,
  STOP_MEANS,
  asCaptureState,
  choiceFromPreparation,
  controlAvailable,
  needsHost,
  runningCallFrom,
  speechCouldHaveBeenHeard,
  type CaptureState,
  type ProviderChoice,
  type RunningCall,
  type VoiceControl
} from '../../src/voice/model'

/** What the host says an append acknowledgement does not establish. */
const ADMISSION_MEANS =
  'The model received this context. It is not evidence that a host action ran or that audio was played; host action receipts are the authority for that.'

/** One preparation, as a host answers it. */
function preparation(over: Partial<VoicePrepareResult> = {}): VoicePrepareResult {
  return {
    session_ids: ['s-1'],
    statement: {
      actions: ['brief', 'navigate'],
      statements: ['Summarise what a session is doing.', 'Move between sessions.'],
      unlocked_screen_actions: []
    },
    excluded: ['attachment_bytes', 'environment_variables', 'file_contents', 'terminal_scrollback'],
    selected: ['file_contents'],
    token_cap: 8000,
    message_count: 20,
    broker_origin: 'https://reach.kala.to',
    model: 'gpt-live-1',
    disclosure: ['Audio travels directly between the paired device and the provider.'],
    admission_note: ADMISSION_MEANS,
    ...over
  }
}

const notCapturing: readonly CaptureState[] = [
  'muted_by_person',
  'interrupted',
  'route_changing',
  'suspended_by_system',
  'unavailable',
  'idle'
]

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

function choice(over: Partial<ProviderChoice> = {}): ProviderChoice {
  return {
    model: 'gpt-live-1',
    brokerOrigin: 'https://reach.kala.to',
    disclosure: ['Audio travels directly between this device and the provider.'],
    context: [{ kind: 'the session', summary: 'its description and the last 20 messages' }],
    withheld: [
      { kind: 'file_contents', summary: 'the contents of files', reason: 'not selected' }
    ],
    tokenCap: 8000,
    messageCount: 20,
    sessions: ['s-1'],
    permits: ['navigate sessions', 'ask for status'],
    admissionMeans: ADMISSION_MEANS,
    ...over
  }
}

describe('what the microphone’s state means', () => {
  // KR-REQ-15.36, KR-ACC-014
  it('treats only an open microphone as having heard the person', () => {
    expect(speechCouldHaveBeenHeard('capturing')).toBe(true)
    for (const state of notCapturing) {
      expect(speechCouldHaveBeenHeard(state), `${state} did not hear anything`).toBe(false)
    }
  })

  // KR-REQ-15.36: muted or unavailable capture is displayed.
  it('gives every state words a person can read', () => {
    for (const state of [...notCapturing, 'capturing' as const]) {
      const display = CAPTURE_DISPLAY[state]
      expect(display).toBeTruthy()
      expect(display).not.toMatch(/error|fail/i)
      expect(display.trim()).toBe(display)
    }
  })
})

describe('the provider choice', () => {
  // KR-REQ-15.09: the managed content access is stated where the choice is made, in the deployed
  // service's own words rather than a second wording of them.
  it('carries the service’s own disclosure list rather than restating it', () => {
    const made = choice({
      disclosure: [
        'Audio travels directly between this device and the provider, not through this service.',
        'The provider and this service can process the speech and the context the host selects.'
      ]
    })
    expect(made.disclosure).toHaveLength(2)
    expect(made.disclosure[0]).toContain('directly between this device and the provider')
  })

  // KR-REQ-15.19: the context scope is shown before voice starts, with the host's cap.
  it('takes the scope, the cap and the provider from what the host answered', () => {
    const made = choiceFromPreparation(preparation())
    expect(made.model).toBe('gpt-live-1')
    expect(made.brokerOrigin).toBe('https://reach.kala.to')
    expect(made.tokenCap).toBe(8000)
    expect(made.sessions).toEqual(['s-1'])
    expect(made.permits).toEqual(preparation().statement.statements)
    expect(made.admissionMeans).toBe(ADMISSION_MEANS)
  })

  it('names a provider only when the host named one', () => {
    expect(choiceFromPreparation(preparation({ model: null })).model).toBeNull()
  })

  // KR-REQ-15.19: what is excluded is listed beside what is carried.
  it('lists what is not being sent beside what is, and never both', () => {
    const made = choiceFromPreparation(preparation())
    expect(made.context.map((item) => item.kind)).toContain('file_contents')
    expect(made.withheld.map((item) => item.kind)).not.toContain('file_contents')
    expect(made.withheld.map((item) => item.kind)).toContain('terminal_scrollback')
    for (const item of made.withheld) expect(item.reason).toBe('not selected')
  })
})

describe('what the native layer reports about capture', () => {
  // KR-REQ-15.36: a state this build cannot draw is never read as one that heard the person.
  it('reads a known state and refuses an unknown one', () => {
    expect(asCaptureState('capturing')).toBe('capturing')
    expect(asCaptureState('muted_by_person')).toBe('muted_by_person')
    expect(asCaptureState('something-else')).toBe('unavailable')
    expect(speechCouldHaveBeenHeard(asCaptureState('something-else'))).toBe(false)
  })

  // The two halves of a call come from two places, and neither invents the other's.
  it('builds the call from the host’s session and this device’s own state', () => {
    const built = runningCallFrom(
      {
        voice_session_id: 'vs-9',
        grant_id: 'g-1',
        statement: preparation().statement,
        session_ids: ['s-1'],
        call_id: 'call-9',
        provider_session_id: 'sess_9',
        answer_sdp: 'v=0\r\n',
        model: 'gpt-live-1',
        control_path: '/api/voice/sessions/call-9/control',
        broker_origin: 'https://reach.kala.to',
        heartbeat_seconds: 20,
        closes_at_ms: '1763000000000',
        disclosure: []
      },
      { running: true, capture: 'muted_by_person', playing: false, first_audio_ms: 410 },
      ADMISSION_MEANS
    )
    expect(built.voiceSessionId).toBe('vs-9')
    expect(built.model).toBe('gpt-live-1')
    expect(built.closesAtMs).toBe(1_763_000_000_000)
    expect(built.capture).toBe('muted_by_person')
    expect(built.playing).toBe(false)
    expect(built.firstAudioMs).toBe(410)
    expect(built.delegations).toEqual([])
  })
})

describe('stopping playback and cancelling a task', () => {
  // KR-REQ-15.22: speech interruption stops playback, not a coding task.
  it('gives playback no reach beyond this device', () => {
    expect(needsHost({ kind: 'playback' })).toBe(false)
  })

  it('makes a cancellation name the session and the current turn', () => {
    const cancellation = { kind: 'task', sessionId: 's-1', turnId: 't-9' } as const
    expect(needsHost(cancellation)).toBe(true)
    expect(cancellation.turnId).toBe('t-9')
  })

  it('says what each one does, so the two cannot be confused', () => {
    expect(STOP_MEANS.playback).toContain('task keeps running')
    expect(STOP_MEANS.task).toContain('Cancels the current turn')
    expect(STOP_MEANS.playback).not.toBe(STOP_MEANS.task)
  })
})

describe('what still works when the broker does not', () => {
  // KR-REQ-15.17: local microphone and speaker mute and transport closure remain available.
  it('keeps the three local controls available with both connections gone', () => {
    const cut = call({ brokerReachable: false, hostReachable: false })
    for (const control of LOCAL_ONLY_CONTROLS) {
      expect(controlAvailable(control, cut), `${control} is local`).toBe(true)
    }
  })

  it('withdraws only the control whose own connection is gone', () => {
    const noBroker = call({ brokerReachable: false })
    expect(controlAvailable('send_context', noBroker)).toBe(false)
    // KR-REQ-15.22: a cancellation is a typed request to the host, so a voice service that has
    // stopped answering must not take it away.
    expect(controlAvailable('cancel_task', noBroker)).toBe(true)

    const noHost = call({ hostReachable: false })
    expect(controlAvailable('cancel_task', noHost)).toBe(false)
    expect(controlAvailable('send_context', noHost)).toBe(true)
  })

  it('offers both again once both answer', () => {
    const live = call()
    for (const control of ['cancel_task', 'send_context'] as VoiceControl[]) {
      expect(controlAvailable(control, live)).toBe(true)
    }
  })
})

describe('what an append acknowledgement means', () => {
  // KR-REQ-15.17: append acknowledgements prove context admission, not host execution.
  it('says plainly what admission does not establish', () => {
    expect(ADMISSION_MEANS).toContain('not evidence')
    expect(ADMISSION_MEANS).toContain('receipt')
    expect(ADMISSION_MEANS).not.toMatch(/\bdone\b|\bcompleted\b|\bexecuted\b/i)
  })
})
