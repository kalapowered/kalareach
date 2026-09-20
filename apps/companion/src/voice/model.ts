/**
 * What a voice call is, as the screen needs to see it.
 *
 * Three things in section 15 are easy to build wrongly, and this model exists to make each of them
 * structural rather than a matter of which button a person presses.
 *
 * **An append acknowledgement is not execution** (¶10). The broker says the model received some
 * context; that is all it says. Host action receipts are the authority for what ran. So an
 * acknowledgement is carried as `admitted` and there is no code path that promotes it to done.
 *
 * **Stopping playback is not cancelling a task** (¶13). They are different operations with
 * different reach: one silences this device's speaker, the other sends a typed cancellation to a
 * host with a turn identifier. They are separate fields, separate calls and separate controls, and
 * the interface must not let a person confuse them.
 *
 * **Local mute and closure survive the broker** (¶10). Muting the microphone, muting the speaker
 * and hanging up act on the native call, never on the control socket. They are correct answers even
 * when nothing can reach the service.
 */

import type { VoicePrepareResult, VoiceSessionDescriptor } from '@kalareach/protocol'

import type { VoiceCallState } from '../host/port'

/** What the microphone is doing, as the native layer reports it. */
export type CaptureState =
  | 'capturing'
  | 'muted_by_person'
  | 'interrupted'
  | 'route_changing'
  | 'suspended_by_system'
  | 'unavailable'
  | 'idle'

/** What a person is told about the microphone, in their own terms. */
export const CAPTURE_DISPLAY: Readonly<Record<CaptureState, string>> = {
  capturing: 'Microphone on',
  muted_by_person: 'Microphone muted',
  interrupted: 'Microphone taken by another call',
  route_changing: 'Switching audio device',
  suspended_by_system: 'Microphone paused by the system',
  unavailable: 'No microphone available',
  idle: 'Not in a call'
}

/**
 * Whether speech could have reached the call in this state.
 *
 * The person's own mute counts as not heard, deliberately: a muted microphone heard nothing,
 * whoever muted it.
 */
export function speechCouldHaveBeenHeard(state: CaptureState): boolean {
  return state === 'capturing'
}

/** One class of content a call would carry, as the scope screen lists it. */
export interface ContextItem {
  /** What class of content it is, in the host's own vocabulary. */
  readonly kind: string
  /** One line a person can read. */
  readonly summary: string
}

/** What the host will not send, and why. Shown beside what it will. */
export interface WithheldItem {
  readonly kind: string
  /** One line a person can read. */
  readonly summary: string
  readonly reason: string
}

/**
 * Everything shown before a call starts.
 *
 * KR-REQ-15.19 asks for the provider and the selected context scope before voice starts, and
 * KR-REQ-15.09 asks for the managed content access to be disclosed in the provider choice. Both are
 * fields here rather than prose in a component, so a test can assert they were shown rather than
 * assert that a paragraph exists.
 *
 * Every field is something a host answered. The screen is not the place where the provider, the
 * disclosure or the scope are decided, and a copy of any of them written here would be a second
 * version of a fact that has an authoritative one.
 */
export interface ProviderChoice {
  /** The model a call would run on, or null when the host names none before the call exists. */
  readonly model: string | null
  /** The service that brokers the call, by origin. */
  readonly brokerOrigin: string
  /**
   * What the provider and the managed operator can see.
   *
   * The host's own disclosure list, carried to the screen untouched. A second wording of the same
   * facts is a second thing to keep true.
   */
  readonly disclosure: readonly string[]
  /** What a call would carry, class by class. */
  readonly context: readonly ContextItem[]
  /** What it would leave out, and why. */
  readonly withheld: readonly WithheldItem[]
  /** The host's own cap on selected context, in tokens. The host is what enforces it. */
  readonly tokenCap: number
  /** How many recent messages the default context carries. */
  readonly messageCount: number
  /** The sessions this call would be able to reach. */
  readonly sessions: readonly string[]
  /** What the voice grant would permit, in the host's own sentences. */
  readonly permits: readonly string[]
  /** What an append acknowledgement does not establish, in the host's own words. */
  readonly admissionMeans: string
}

/** How a content class reads to a person. */
function classSummary(kind: string): string {
  switch (kind) {
    case 'file_contents':
      return 'the contents of files'
    case 'environment_variables':
      return 'environment variables'
    case 'terminal_scrollback':
      return 'raw terminal scrollback'
    case 'attachment_bytes':
      return 'the bytes of an attachment'
    default:
      return kind.replace(/_/g, ' ')
  }
}

/**
 * The choice screen's view of what a host answered.
 *
 * The one place a preparation becomes something a person reads, so the screen has no second route
 * to a provider name, a disclosure or a scope.
 */
export function choiceFromPreparation(preparation: VoicePrepareResult): ProviderChoice {
  return {
    model: preparation.model,
    brokerOrigin: preparation.broker_origin,
    disclosure: preparation.disclosure,
    context: [
      {
        kind: 'the session',
        summary: `its description, working directory, active application, decisions waiting on you and the last ${preparation.message_count} messages`
      },
      ...preparation.selected.map((kind) => ({ kind, summary: classSummary(kind) }))
    ],
    withheld: preparation.excluded
      .filter((kind) => !preparation.selected.includes(kind))
      .map((kind) => ({ kind, summary: classSummary(kind), reason: 'not selected' })),
    tokenCap: preparation.token_cap,
    messageCount: preparation.message_count,
    sessions: preparation.session_ids,
    permits: preparation.statement.statements,
    admissionMeans: preparation.admission_note
  }
}

/** What happened to one context request this client sent. */
export type ContextOutcome =
  /** Sent, and the service has not answered yet. */
  | 'sent'
  /** The service accepted it and passed it on. */
  | 'accepted'
  /**
   * The provider acknowledged it.
   *
   * Admission, and nothing more. It is not evidence that a host action ran or that audio played.
   */
  | 'admitted'
  /** The service refused it. */
  | 'refused'

/** One context request this client sent, and where it got to. */
export interface ContextRequest {
  readonly id: string
  readonly command: string
  readonly outcome: ContextOutcome
  /** The refusal's reason, when it was refused. */
  readonly reason?: string
}

/** One delegation the provider announced during the call. */
export interface Delegation {
  /** The provider's opaque identifier. Correlation data, never authority. */
  readonly delegationId: string
  /** Where in the call it happened, in milliseconds from the start. */
  readonly offsetMs: number
  /** What the host did with it, once it was submitted. */
  readonly state: 'announced' | 'submitted' | 'needs_confirmation' | 'refused' | 'receipted'
  /** The host's own words, when it refused or receipted. */
  readonly detail?: string
}

/** A call that is running, as the screen sees it. */
export interface RunningCall {
  readonly voiceSessionId: string
  readonly callId: string
  readonly model: string
  readonly closesAtMs: number
  readonly capture: CaptureState
  /** Whether the model's voice is coming out of this device. */
  readonly playing: boolean
  /** Whether the control socket to the voice service is carrying requests. */
  readonly brokerReachable: boolean
  /**
   * Whether this device's connection to the host is carrying requests.
   *
   * A different connection from the control socket, and the difference matters: cancelling a turn
   * is a typed request to a host, so it survives a voice service that has stopped answering and
   * fails when the host is the thing that is gone.
   */
  readonly hostReachable: boolean
  readonly delegations: readonly Delegation[]
  readonly requests: readonly ContextRequest[]
  /** Milliseconds from the answer being applied to the first remote audio. KR-PERF-010. */
  readonly firstAudioMs: number | null
  /**
   * What an append acknowledgement does not establish, in the host's own words.
   *
   * Shown with every admitted request, because a person reading "acknowledged" next to a
   * delegation would otherwise reasonably conclude the work was done.
   */
  readonly admissionMeans: string
}

/**
 * The call the screen holds, built from what the host answered and what this device reports.
 *
 * The two halves are deliberately different sources. The session, the model and the closing time
 * are the host's; the microphone, the speaker and the first audio are this device's, read from the
 * call it is holding. Nothing here is a guess about either.
 */
export function runningCallFrom(
  session: VoiceSessionDescriptor,
  state: VoiceCallState,
  admissionMeans: string
): RunningCall {
  return {
    voiceSessionId: session.voice_session_id,
    callId: session.call_id,
    model: session.model,
    closesAtMs: Number(session.closes_at_ms),
    capture: asCaptureState(state.capture),
    playing: state.playing,
    brokerReachable: true,
    hostReachable: true,
    delegations: [],
    requests: [],
    firstAudioMs: state.first_audio_ms,
    admissionMeans
  }
}

/** Every capture state the surface can draw, by its wire name. */
const CAPTURE_STATES: readonly CaptureState[] = [
  'capturing',
  'muted_by_person',
  'interrupted',
  'route_changing',
  'suspended_by_system',
  'unavailable',
  'idle'
]

/**
 * Reads the native layer's word for what the microphone is doing.
 *
 * A word this build does not draw becomes `unavailable` rather than `capturing`: an unknown state
 * is not one in which speech is known to have been heard, and the refusal of an unheard claim is
 * built on exactly that distinction.
 */
export function asCaptureState(reported: string): CaptureState {
  return CAPTURE_STATES.find((known) => known === reported) ?? 'unavailable'
}

/**
 * The two things a person can stop, kept apart.
 *
 * Section 15 ¶13: speech interruption stops playback, not a coding task; agent cancellation uses
 * its typed request and current turn identifier. They are named here as a closed pair so that no
 * caller can reach one while meaning the other, and so a test can assert the reach of each.
 */
export type StopKind =
  /** Silences this device's speaker. Reaches no host and cancels nothing. */
  | 'playback'
  /** Sends a typed cancellation for one turn to the host. Does not silence anything. */
  | 'task'

/** What a stop of each kind actually does, in one line a person reads before confirming. */
export const STOP_MEANS: Readonly<Record<StopKind, string>> = {
  playback: 'Stops the voice speaking. The task keeps running.',
  task: 'Cancels the current turn on the host. The voice keeps talking until you stop it.'
}

/** Which host session and turn a task cancellation names. */
export interface TaskCancellation {
  readonly kind: 'task'
  readonly sessionId: string
  /** The turn the host is on now. A stale one is refused by the host. */
  readonly turnId: string
}

/** Silencing the speaker. It carries no session and no turn, because it reaches no host. */
export interface PlaybackStop {
  readonly kind: 'playback'
}

/** Either stop, as the one function that performs them takes it. */
export type StopRequest = PlaybackStop | TaskCancellation

/**
 * Whether a stop request needs the host.
 *
 * The whole separation in one predicate: playback never does, cancellation always does. It is what
 * lets the interface keep the playback control alive while the broker is unreachable and correctly
 * disable the cancellation control, rather than the other way round.
 */
export function needsHost(request: StopRequest): boolean {
  return request.kind === 'task'
}

/**
 * The controls that keep working when the broker does not.
 *
 * KR-REQ-15.17: local microphone and speaker mute and transport closure remain available if the
 * broker fails. Enumerated rather than described, so the test that proves it names the same set the
 * screen enables.
 */
export const LOCAL_ONLY_CONTROLS = ['mute_microphone', 'mute_playback', 'hang_up'] as const

/** One control the call screen offers. */
export type VoiceControl = (typeof LOCAL_ONLY_CONTROLS)[number] | 'cancel_task' | 'send_context'

/**
 * Whether a control can be used right now.
 *
 * The three local ones are available whenever a call is running, whatever else is reachable. The
 * other two each depend on the one connection they actually use: sending context needs the voice
 * service, and cancelling a turn needs the host. Treating those two as one availability would
 * disable a cancellation because a voice service stopped answering, which is the opposite of what
 * section 15 paragraph 10 asks for.
 */
export function controlAvailable(control: VoiceControl, call: RunningCall): boolean {
  if ((LOCAL_ONLY_CONTROLS as readonly string[]).includes(control)) return true
  return control === 'cancel_task' ? call.hostReachable : call.brokerReachable
}
