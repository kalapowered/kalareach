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

/** One thing the host chose to send, as the scope screen lists it. */
export interface ContextItem {
  /** What class of content it is, in the host's own vocabulary. */
  readonly kind: string
  /** One line a person can read. */
  readonly summary: string
  /** How many of this host's tokens it is estimated to take. */
  readonly tokens: number
}

/** What the host will not send, and why. Shown beside what it will. */
export interface WithheldItem {
  readonly kind: string
  readonly reason: string
}

/**
 * Everything shown before a call starts.
 *
 * KR-REQ-15.19 asks for the provider and the selected context scope before voice starts, and
 * KR-REQ-15.09 asks for the managed content access to be disclosed in the provider choice. Both are
 * fields here rather than prose in a component, so a test can assert they were shown rather than
 * assert that a paragraph exists.
 */
export interface ProviderChoice {
  /** The model a call would run on, as the host named it. */
  readonly model: string
  /** The service that brokers the call, by origin. */
  readonly brokerOrigin: string
  /**
   * What the provider and the managed operator can see.
   *
   * This is the deployed service's own disclosure list, carried through the host untouched. A
   * second wording of the same facts is a second thing to keep true.
   */
  readonly disclosure: readonly string[]
  /** What the host has selected to send. */
  readonly context: readonly ContextItem[]
  /** What it will not send, and why. */
  readonly withheld: readonly WithheldItem[]
  /** The host's own cap on selected context, in tokens. */
  readonly tokenCap: number
  /** The sessions this call would be able to reach. */
  readonly sessions: readonly string[]
  /** What the voice grant would permit, action by action. */
  readonly permits: readonly string[]
}

/** The estimated tokens the selected context takes. */
export function selectedTokens(choice: ProviderChoice): number {
  return choice.context.reduce((total, item) => total + item.tokens, 0)
}

/** Whether the selection is inside the host's cap. */
export function withinCap(choice: ProviderChoice): boolean {
  return selectedTokens(choice) <= choice.tokenCap
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

/**
 * What an append acknowledgement does not establish.
 *
 * Shown with every admitted request, because a person reading "acknowledged" next to a delegation
 * would otherwise reasonably conclude the work was done.
 */
export const ADMISSION_MEANS =
  'The model received this. It is not evidence that anything ran on a host; the host’s own receipt '
  + 'is what says that.'

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
  /** Whether the control socket is carrying requests. */
  readonly brokerReachable: boolean
  readonly delegations: readonly Delegation[]
  readonly requests: readonly ContextRequest[]
  /** Milliseconds from the answer being applied to the first remote audio. KR-PERF-010. */
  readonly firstAudioMs: number | null
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
 * The three local ones are available whenever a call is running, whatever the broker is doing. The
 * two that reach something else are not.
 */
export function controlAvailable(control: VoiceControl, call: RunningCall): boolean {
  if ((LOCAL_ONLY_CONTROLS as readonly string[]).includes(control)) return true
  return call.brokerReachable
}
