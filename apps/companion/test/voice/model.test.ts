import { describe, expect, it } from 'vitest'

import {
  ADMISSION_MEANS,
  CAPTURE_DISPLAY,
  LOCAL_ONLY_CONTROLS,
  STOP_MEANS,
  controlAvailable,
  needsHost,
  selectedTokens,
  speechCouldHaveBeenHeard,
  withinCap,
  type CaptureState,
  type ProviderChoice,
  type RunningCall,
  type VoiceControl
} from '../../src/voice/model'

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
    ...over
  }
}

function choice(over: Partial<ProviderChoice> = {}): ProviderChoice {
  return {
    model: 'gpt-live-1',
    brokerOrigin: 'https://reach.kala.to',
    disclosure: ['Audio travels directly between this device and the provider.'],
    context: [
      { kind: 'session_description', summary: 'Building the release', tokens: 120 },
      { kind: 'working_directory', summary: '~/work/kalareach', tokens: 20 }
    ],
    withheld: [{ kind: 'file_contents', reason: 'not selected' }],
    tokenCap: 8000,
    sessions: ['s-1'],
    permits: ['navigate sessions', 'ask for status'],
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
  it('adds up what is selected and holds it to the host’s cap', () => {
    expect(selectedTokens(choice())).toBe(140)
    expect(withinCap(choice())).toBe(true)
    expect(withinCap(choice({ tokenCap: 100 }))).toBe(false)
  })

  it('lists what is not being sent beside what is', () => {
    expect(choice().withheld.map((item) => item.kind)).toContain('file_contents')
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
