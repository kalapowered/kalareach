import { describe, expect, it } from 'vitest'

import type { VoiceManagedTerms, VoicePrepareResult } from '@kalareach/protocol'

import type { VoiceCallState, VoiceClosure, VoiceEnded } from '../../src/host/port'

import {
  CAPTURE_DISPLAY,
  LOCAL_ONLY_CONTROLS,
  NOT_ACTED_ON_WORDS,
  STOP_MEANS,
  asCaptureState,
  callAsReported,
  callLength,
  choiceFromPreparation,
  choiceWithRate,
  closureWords,
  controlAvailable,
  endedWords,
  needsHost,
  owedWords,
  rateWords,
  requestedSeconds,
  runningCallFrom,
  serviceWords,
  speechCouldHaveBeenHeard,
  type CaptureState,
  type ProviderChoice,
  type RunningCall,
  type VoiceControl
} from '../../src/voice/model'

/** How a call that ended on this device ended, with the host's grant withdrawn. */
function endedFor(): VoiceEnded {
  return {
    cause: 'native_ended',
    words: 'The call ended on this device.',
    closed_locally: true,
    host: { kind: 'revoked', fence: { kind: 'not_owed' }, broker_notified: true },
    broker: 'closed_by_host'
  }
}

/** What the host says an append acknowledgement does not establish. */
const ADMISSION_MEANS =
  'The model received this context. It is not evidence that a host action ran or that audio was played; host action receipts are the authority for that.'

/** The managed service's terms, as a host carries them. */
function terms(over: Partial<VoiceManagedTerms> = {}): VoiceManagedTerms {
  return {
    enabled: true,
    model: 'gpt-live-1',
    disclosure: ['Audio travels directly between this device and the provider.'],
    admission_note: ADMISSION_MEANS,
    delegation_note: 'A provider delegation identifier is correlation data.',
    alternatives: ['The coding agent already running on the host.'],
    rate: { version: '2026-09-a', minor_units_per_second: '2', minimum_seconds: 15, currency: 'usd' },
    maximum_session_seconds: 1800,
    minimum_request_seconds: 60,
    heartbeat_seconds: 20,
    context_bytes: 500,
    ...over
  }
}

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
    prepared: 'AAAA',
    managed: terms(),
    managed_unavailable: null,
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

/** The state of a call the device holds, as it reports it. */
function callState(over: Partial<VoiceCallState> = {}): VoiceCallState {
  return {
    running: true,
    setting_up: false,
    ending: false,
    capture: 'capturing',
    playing: true,
    control: 'connected',
    host: 'reachable',
    session: null,
    ended: null,
    delegations: [],
    warning: null,
    owed: [],
    ...over
  }
}

function choice(over: Partial<ProviderChoice> = {}): ProviderChoice {
  return {
    brokerOrigin: 'https://reach.kala.to',
    prepared: 'scope-1',
    managed: terms(),
    unavailable: null,
    previousRate: null,
    context: [{ kind: 'the session', summary: 'its description and the last 20 messages' }],
    withheld: [
      { kind: 'file_contents', summary: 'the contents of files', reason: 'not selected' }
    ],
    tokenCap: 8000,
    messageCount: 20,
    sessions: ['s-1'],
    sessionNames: {},
    permits: ['navigate sessions', 'ask for status'],
    needsUnlockedScreen: false,
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
  it('carries the service’s own terms rather than restating them', () => {
    const published = terms({
      disclosure: [
        'Audio travels directly between this device and the provider, not through this service.',
        'The provider and this service can process the speech and the context the host selects.'
      ]
    })
    const made = choiceFromPreparation(preparation({ managed: published }))
    expect(made.managed).toEqual(published)
    expect(made.unavailable).toBeNull()
  })

  // KR-REQ-15.19: the context scope is shown before voice starts, with the host's cap.
  it('takes the scope, the cap and the provider from what the host answered', () => {
    const made = choiceFromPreparation(preparation())
    expect(made.managed?.model).toBe('gpt-live-1')
    expect(made.brokerOrigin).toBe('https://reach.kala.to')
    expect(made.tokenCap).toBe(8000)
    expect(made.sessions).toEqual(['s-1'])
    expect(made.permits).toEqual(preparation().statement.statements)
    expect(made.needsUnlockedScreen).toBe(false)
  })

  // KR-REQ-15.19: without the service's terms there is nothing to accept, and the host's reason is
  // what the person reads.
  it('carries the host’s reason when it has no terms to show', () => {
    const made = choiceFromPreparation(
      preparation({ managed: null, managed_unavailable: 'The managed service did not answer.' })
    )
    expect(made.managed).toBeNull()
    expect(made.unavailable).toBe('The managed service did not answer.')

    const silent = choiceFromPreparation(preparation({ managed: null, managed_unavailable: null }))
    expect(silent.unavailable).toBeTruthy()
  })

  // A refused start moves only the rate, and the rate the person read before stays beside it.
  it('replaces the rate after a refusal and keeps the one read before', () => {
    const before = choice()
    const rate = { version: '2026-10-b', minor_units_per_second: '3', minimum_seconds: 15, currency: 'usd' }
    const after = choiceWithRate(before, rate)
    expect(after.managed?.rate.version).toBe('2026-10-b')
    expect(after.previousRate?.version).toBe('2026-09-a')
    expect(after.managed?.disclosure).toEqual(before.managed?.disclosure)
    expect(choiceWithRate(choice({ managed: null }), rate).managed).toBeNull()
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
      callState({ capture: 'muted_by_person', playing: false, control: 'unreachable' }),
      ADMISSION_MEANS
    )
    expect(built.voiceSessionId).toBe('vs-9')
    expect(built.model).toBe('gpt-live-1')
    expect(built.closesAtMs).toBe(1_763_000_000_000)
    expect(built.capture).toBe('muted_by_person')
    expect(built.playing).toBe(false)
    expect(built.delegations).toEqual([])
    // Whether the voice service answers is the call's own report about its control channel.
    expect(built.brokerReachable).toBe(false)
    expect(built.sessions).toEqual(['s-1'])
  })
})

describe('what the device reports of its call', () => {
  // The call is the application's, so the screen takes its microphone, its speaker, the voice
  // service, the host the call belongs to and the delegations from the device's report, whoever
  // started the call.
  it('takes every fact of a held call from the device\'s report', () => {
    const reported = callAsReported(
      call(),
      callState({
        capture: 'interrupted',
        playing: false,
        control: 'unreachable',
        host: 'lost',
        delegations: [{ delegation_id: 'd-1', offset_ms: 1200, state: 'not_done', told: true }]
      })
    )
    expect(reported.capture).toBe('interrupted')
    expect(reported.playing).toBe(false)
    expect(reported.brokerReachable).toBe(false)
    expect(reported.callHost).toBe('lost')
    expect(reported.delegations).toEqual([{ delegationId: 'd-1', offsetMs: 1200, told: true }])
    expect(reported.voiceSessionId).toBe('vs-1')
  })

  it('says that this version acts on no spoken request', () => {
    expect(NOT_ACTED_ON_WORDS).toMatch(/^Not done: this version does not act on spoken requests/)
  })
})

describe('what a call that ended tells a person', () => {
  const ended = (over: Partial<VoiceEnded> = {}): VoiceEnded => ({
    cause: 'native_ended',
    words: 'The call ended on this device.',
    closed_locally: true,
    host: { kind: 'revoked', fence: { kind: 'not_owed' }, broker_notified: true },
    broker: 'closed_by_host',
    ...over
  })

  it('says the host withdrew the grant when it answered', () => {
    const words = endedWords(ended())
    expect(words).toContain('The call ended on this device.')
    expect(words).toContain("The host withdrew the call's grant.")
    expect(words).not.toContain('may still be open')
  })

  // The grant may be live until the call was to close, so the host's silence is said as owed.
  // What happened is said in the past tense, and whether the grant may still be open is said by what
  // is owed, which lapses with the grant: the words of the end do not outlive it.
  it('says the host did not confirm that it withdrew the grant, and not that it may still be open', () => {
    const words = endedWords(ended({ host: { kind: 'not_told', words: 'The host could not be reached.' } }))
    expect(words).toContain(
      "The host did not confirm that it withdrew the call's grant: The host could not be reached."
    )
    expect(words).not.toContain('The host withdrew')
    expect(words).not.toContain('may still be open')
  })

  // A refusal does not say the grant is gone, so the words say only that the host did not confirm
  // it; whether it may still be open is said by what is owed.
  it('says the host refused the stop and did not confirm that it withdrew the grant', () => {
    const words = endedWords(ended({ host: { kind: 'refused', words: 'No such voice session.' } }))
    expect(words).toContain('No such voice session.')
    expect(words).toContain("did not confirm that it withdrew the call's grant: it refused the stop")
    expect(words).not.toContain('would not revoke')
  })

  it('says when the media may not have stopped', () => {
    const words = endedWords(ended({ closed_locally: false }))
    expect(words).toContain("could not confirm that the call's microphone stopped")
    expect(endedWords(ended())).not.toContain('microphone stopped')
  })

  it('says nothing of a host that was never asked, and keeps the fence it has still to confirm', () => {
    expect(endedWords(ended({ host: { kind: 'not_needed' } }))).toBe('The call ended on this device.')
    const pending = endedWords(
      ended({ host: { kind: 'revoked', fence: { kind: 'unreadable' }, broker_notified: false } })
    )
    expect(pending).toContain('cannot confirm that nothing the call sent can still run')
  })
})

describe('what is owed', () => {
  // The record's own words are the reason; what is owed, and until when, is said with them.
  it('says until when a grant the host may hold open stays so', () => {
    const words = owedWords({
      kind: 'revocation',
      words: 'The host could not be reached in time.',
      action_id: null,
      voice_session_id: 'vs-1',
      until_ms: Date.UTC(2026, 9, 17, 12, 30),
      host_reference: 'ref-1',
      host_name: "Ric's Mac"
    })
    expect(words).toContain("Ric's Mac may still hold a grant for this call open. It ends by itself by")
    expect(words).toContain('The host could not be reached in time.')
  })

  it('names the host a start that was never answered was asked of', () => {
    const words = owedWords({
      kind: 'start_unknown',
      words: 'The host never said whether it created the call.',
      action_id: 'a-1',
      voice_session_id: null,
      until_ms: 1,
      host_reference: 'ref-1',
      host_name: "Ric's Mac"
    })
    expect(words).toBe("The host never said whether it created the call. It was asked of Ric's Mac.")
  })
})

describe('what the voice service did about a call that ended', () => {
  // The service is asked last and the screen does not wait for it, so what it did is said apart
  // from the rest of the end, once it is known.
  it('says nothing while the service has still to answer, or when it closed the call', () => {
    for (const broker of ['pending', 'closed', 'closed_by_host', 'closed_by_service', 'closed_over_http', 'not_needed']) {
      expect(serviceWords({ ...endedFor(), broker })).toBeNull()
    }
  })

  it('says the service has not confirmed, and that a call this device cannot name may be held', () => {
    expect(serviceWords({ ...endedFor(), broker: 'not_confirmed' })).toContain(
      'has not confirmed that it closed the call'
    )
    expect(serviceWords({ ...endedFor(), broker: 'unknown' })).toContain(
      'cannot name it to close it'
    )
  })
})

describe('what the screen says when it ends a call', () => {
  const none = (over: Partial<VoiceClosure> = {}): VoiceClosure => ({
    closed_locally: true,
    fence: { kind: 'not_owed' },
    host_failure: null,
    not_held: false,
    ...over
  })

  it('adds nothing when the call stopped here and the host owed no fence', () => {
    expect(closureWords(none())).toBeNull()
  })

  // The microphone is the first thing a person wants to know stopped.
  it('does not say the call is closed when this device could not confirm the media stopped', () => {
    const words = closureWords(none({ closed_locally: false }))
    expect(words).toContain("could not confirm that the call's microphone stopped")
    expect(words).not.toContain('is closed')
  })

  // A reader must not take "and its grant withdrawn" to be what could not be confirmed.
  it('keeps the unconfirmed microphone apart from a grant that was withdrawn', () => {
    const words = closureWords(
      none({
        closed_locally: false,
        fence: { kind: 'unreadable' }
      })
    )
    expect(words).toContain("could not confirm that the call's microphone stopped.")
    expect(words).toContain("The host withdrew the call's grant.")
    expect(words).not.toContain('and its grant withdrawn')
  })

  it('says the host did not confirm when it could not be told or did not answer', () => {
    const words = closureWords(
      none({
        fence: null,
        host_failure: { code: 'RESOURCE_UNAVAILABLE', message: 'RESOURCE_UNAVAILABLE: No answer.', user_action: 'wait' }
      })
    )
    expect(words).toContain("This device's call is closed.")
    expect(words).toContain('The host did not confirm that it withdrew the grant: No answer.')
    expect(words).not.toContain('RESOURCE_UNAVAILABLE')
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

  it('ties the two host requests to the host and to nothing the voice service does', () => {
    const noBroker = call({ brokerReachable: false })
    // KR-REQ-15.22: a cancellation is a typed request to the host, so a voice service that has
    // stopped answering must not take it away; neither does it take away reading the selection.
    expect(controlAvailable('cancel_task', noBroker)).toBe(true)
    expect(controlAvailable('host_selection', noBroker)).toBe(true)

    const noHost = call({ hostReachable: false })
    expect(controlAvailable('cancel_task', noHost)).toBe(false)
    expect(controlAvailable('host_selection', noHost)).toBe(false)
  })

  it('offers both again once the host answers', () => {
    const live = call()
    for (const control of ['cancel_task', 'host_selection'] as VoiceControl[]) {
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

describe('what a call costs', () => {
  // KR-REQ-15.19: the rate is shown in the service's currency, the way the person's locale writes
  // money, from whole minor units a second.
  it('writes the rate a second and a minute from minor units', () => {
    const words = rateWords(
      { version: 'v', minor_units_per_second: '2', minimum_seconds: 15, currency: 'usd' },
      'en-GB'
    )
    expect(words.perSecond).toBe('US$0.02')
    expect(words.perMinute).toBe('US$1.20')
    expect(words.ceiling(1800)).toBe('US$36.00')
    // A call shorter than the provider's minimum is charged the minimum.
    expect(words.ceiling(5)).toBe('US$0.30')
  })

  it('shifts by the currency’s own decimal places', () => {
    const yen = rateWords(
      { version: 'v', minor_units_per_second: '3', minimum_seconds: 15, currency: 'jpy' },
      'en-GB'
    )
    expect(yen.perSecond).toBe('JP¥3')
    expect(yen.perMinute).toBe('JP¥180')
  })

  it('does not guess at an amount or a currency it cannot read', () => {
    const odd = rateWords(
      { version: 'v', minor_units_per_second: '2.5', minimum_seconds: 15, currency: 'usd' },
      'en-GB'
    )
    expect(odd.perSecond).toBe('2.5 minor units of USD')
    expect(odd.perMinute).toBeNull()
    expect(odd.ceiling(60)).toBeNull()

    const unknown = rateWords(
      { version: 'v', minor_units_per_second: '2', minimum_seconds: 15, currency: 'not-a-code' },
      'en-GB'
    )
    expect(unknown.perSecond).toBe('2 minor units of NOT-A-CODE')
  })

  // A start never asks for longer than the service authorises, which it would refuse.
  it('asks for half an hour or the service’s maximum, whichever is shorter', () => {
    expect(requestedSeconds(terms())).toBe(1800)
    expect(requestedSeconds(terms({ maximum_session_seconds: 600 }))).toBe(600)
    expect(requestedSeconds(terms({ maximum_session_seconds: 30 }))).toBeNull()
  })

  it('names a call length the way a person says it', () => {
    expect(callLength(1800)).toBe('30 minutes')
    expect(callLength(60)).toBe('1 minute')
    expect(callLength(15)).toBe('15 seconds')
  })
})
