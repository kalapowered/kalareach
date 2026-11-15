/**
 * What a person reads about pairing, in one place so it can be localised.
 *
 * Native code decides which outcome an attempt ended with; this file holds the words for each, and
 * the one thing the person can do next. An authentication failure stays ambiguous on purpose: the
 * code, the service or the host may be wrong, and saying which would be a guess.
 */

import type { PairingFailure, PairingSources } from '../host/port'

/** What the person can do next, after an attempt ends. */
export type NextAction =
  | 'fix_code'
  | 'new_code'
  | 'try_again'
  | 'change_service'
  | 'start_again'
  | 'new_invitation'
  | 'open_settings'
  | 'done'

/** How an attempt was made. */
export type AttemptMode = 'code' | 'direct'

/** Where a person brings an invitation in from on this device, best first. */
export type Reading = 'camera' | 'photo' | 'pasteboard'

/** Where this device brings an invitation in from: the scanner when it has one, else the picker. */
export function readingFrom(sources: PairingSources | undefined): Reading {
  if (sources?.camera === true) return 'camera'
  return sources?.photo === true ? 'photo' : 'pasteboard'
}

/** What a person does to bring the same invitation in again, as a clause that starts a sentence. */
function bringItInAgain(reading: Reading): string {
  switch (reading) {
    case 'camera':
      return 'Scan the invitation again'
    case 'photo':
      return 'Choose the picture again'
    case 'pasteboard':
      return 'Copy the invitation from the host again'
  }
}
/**
 * The words and the next action for one failure of an attempt made in `mode`. `service` is the
 * host name of the service a code attempt went through.
 */
export function failureWords(
  failure: Pick<PairingFailure, 'kind' | 'retry_after_seconds'>,
  service: string,
  mode: AttemptMode = 'code',
  reading: Reading = 'pasteboard'
): { readonly sentence: string; readonly action: NextAction } {
  const words = codeWords(failure, service, reading)
  if (mode === 'code') return words
  // A direct invitation reaches no service and holds no code, and native code lets it go once the
  // attempt ends: it is tried again only by bringing it in again.
  switch (failure.kind) {
    case 'not_authenticated':
      return {
        sentence: 'The invitation did not work. Ask the host for a new one.',
        action: 'new_invitation'
      }
    case 'did_not_finish':
      return {
        sentence: `Pairing did not finish. ${bringItInAgain(reading)}, or ask the host for a new one.`,
        action: 'new_invitation'
      }
    default:
      return words.action === 'done' ? words : { sentence: words.sentence, action: 'new_invitation' }
  }
}

/** The words and the next action for one failure of a code attempt through `service`. */
function codeWords(
  failure: Pick<PairingFailure, 'kind' | 'retry_after_seconds'>,
  service: string,
  reading: Reading
): { readonly sentence: string; readonly action: NextAction } {
  switch (failure.kind) {
    case 'malformed':
      return {
        sentence: 'A code has ten characters, and never contains 0, O, I or l.',
        action: 'fix_code'
      }
    case 'device_tries_used':
      return {
        sentence:
          'This code has been tried five times on this device. Ask the host for a new code.',
        action: 'new_code'
      }
    case 'service_unreachable':
      return {
        sentence: `${service} could not be reached. Check this device's connection and try again.`,
        action: 'try_again'
      }
    case 'service_not_pairing':
      return {
        sentence: `${service} does not offer pairing. Check the service in pairing settings.`,
        action: 'change_service'
      }
    case 'no_host_answered':
      return {
        sentence:
          'No host answered for this code. Check the code and that the host is online. A code lasts five minutes.',
        action: 'try_again'
      }
    case 'not_authenticated':
      return {
        sentence: 'The code did not work. Check it on the host and try again.',
        action: 'fix_code'
      }
    case 'host_tries_used':
      return {
        sentence:
          'The host reports that too many wrong codes were tried, so it ended this invitation. Ask for a new code.',
        action: 'new_code'
      }
    case 'expired':
      return {
        sentence: 'The host reports that the invitation expired. Ask it for a new one.',
        action: 'start_again'
      }
    case 'timed_out':
      return { sentence: 'The host did not finish the exchange in time. Try again.', action: 'try_again' }
    case 'declined':
      return { sentence: 'The owner declined this device on the host.', action: 'done' }
    case 'withdrawn':
      return { sentence: 'The invitation was withdrawn on the host.', action: 'done' }
    case 'host_restarted':
      return {
        sentence: 'The host restarted before pairing finished. Ask for a new invitation.',
        action: 'start_again'
      }
    case 'another_device_waiting':
      return {
        sentence: 'Another device is already waiting for approval on this invitation.',
        action: 'done'
      }
    case 'host_unreachable':
      return {
        sentence:
          "The host could not be reached. Check that this device is on the host's network, or that the host is online.",
        action: 'try_again'
      }
    case 'relay_capacity':
      return {
        // The managed relay is the product's own, so the failure is not the host's, and it is said
        // to be neither. The way round it that fits both ways of pairing is the host's own network.
        sentence: `The managed relay could not take this pairing now. Try again in about ${waitInWords(failure.retry_after_seconds)}, or bring this device onto the host's network.`,
        action: 'try_again'
      }
    case 'relay_fault':
      return {
        sentence: `The managed relay service could not admit this pairing now. This is not a fault of the host. Try again in about ${waitInWords(failure.retry_after_seconds)}, or bring this device onto the host's network.`,
        action: 'try_again'
      }
    case 'host_mismatch':
      return {
        sentence: 'The host did not match its invitation, so KalaReach stopped before pairing.',
        action: 'done'
      }
    case 'already_paired':
      return { sentence: 'This device is already paired with this host.', action: 'done' }
    case 'not_an_invitation':
      return { sentence: 'That is not a KalaReach invitation.', action: 'new_invitation' }
    case 'newer_invitation':
      return { sentence: 'This invitation needs a newer version of KalaReach.', action: 'done' }
    case 'nothing_to_paste':
      return {
        sentence:
          'The clipboard holds no invitation. Copy the invitation text from the host, then paste again.',
        action: 'new_invitation'
      }
    case 'camera_denied':
      return {
        sentence: 'KalaReach cannot use the camera. Allow it in Settings if this phone lets you, or type the code.',
        action: 'open_settings'
      }
    case 'no_code_found':
      return {
        sentence: `No KalaReach invitation was found in that picture. ${
          reading === 'photo' ? 'Choose another picture' : 'Choose another picture, or scan the code'
        }.`,
        action: 'new_invitation'
      }
    case 'reader_failed':
      return {
        sentence:
          reading === 'photo'
            ? 'That picture could not be opened. Choose another picture, or scan the code.'
            : 'The camera could not be started. Close anything else that is using it and try again, or type the code.',
        action: 'new_invitation'
      }
    case 'store_failed':
      return {
        sentence:
          "KalaReach could not keep this device's pairing records safely, so it stopped. Nothing was sent.",
        action: 'done'
      }
    case 'approval_unknown':
      return {
        sentence:
          'The host may have approved this device while KalaReach could not ask, but KalaReach cannot confirm that. Ask the owner to check the host.',
        action: 'done'
      }
    case 'did_not_finish':
    default:
      // A kind this build does not know, from a newer native side, says no more than this.
      return {
        sentence: 'Pairing did not finish. Try again, or ask the host for a new invitation.',
        action: 'try_again'
      }
  }
}

/** The longest wait the page says: a wait above it is said as this one. */
const LONGEST_SAID_SECONDS = 24 * 60 * 60

/**
 * How long a wait of `seconds` is said to be, in the one unit that fits it and rounded up, so that
 * a person is never told to try again before this device would. It is said as the host's own line
 * says it: a figure of 0 is "1 second", and one above a day is "24 hours". A figure that is no
 * finite number is said as the longest wait, never as a shorter one.
 */
export function waitInWords(seconds: number | undefined): string {
  const said =
    seconds !== undefined && Number.isFinite(seconds)
      ? Math.min(Math.max(Math.ceil(seconds), 1), LONGEST_SAID_SECONDS)
      : LONGEST_SAID_SECONDS
  const minutes = Math.ceil(said / 60)
  if (said === 1) return '1 second'
  if (said < 60) return `${said} seconds`
  if (minutes === 1) return '1 minute'
  if (minutes < 60) return `${minutes} minutes`
  const hours = Math.ceil(minutes / 60)
  return hours === 1 ? '1 hour' : `${hours} hours`
}

/** What the screen says once before the paths a failure names. */
export const UNTIL_THEN = 'Until then:'

/**
 * The paths that still work, each exactly as the managed relay service wrote it and in the order it
 * wrote them. Only a failure for want of capacity has any, and only when the service named at
 * least one: the kind decides, so a failure of any other kind shows none, whatever else it holds.
 */
export function failureAlternatives(
  failure: Pick<PairingFailure, 'kind' | 'alternatives'>
): readonly string[] {
  return failure.kind === 'relay_capacity' ? (failure.alternatives ?? []) : []
}

/** The whole sentence for a failure, with the tries line whenever the attempt was charged. */
export function failureSentence(
  failure: PairingFailure,
  service: string,
  mode: AttemptMode = 'code',
  reading: Reading = 'pasteboard'
): string {
  const { sentence } = failureWords(failure, service, mode, reading)
  if (failure.tries_left === null) return sentence
  const tries = failure.tries_left === 1 ? '1 try' : `${failure.tries_left} tries`
  return `${sentence} ${tries} left on this device.`
}

/**
 * Whether a failure's next action tries the same code again: fixing a character, trying again, or
 * trying it through another service. Only then does the typed code stay in its field; after any
 * other ending it is spent, and the page lets it go.
 */
export function triesTheCodeAgain(action: NextAction): boolean {
  return action === 'fix_code' || action === 'try_again' || action === 'change_service'
}

/** The label of the button that does a failure's next action. */
export function actionLabel(action: NextAction, reading: Reading = 'pasteboard'): string {
  switch (action) {
    case 'fix_code':
    case 'try_again':
      return 'Try again'
    case 'new_code':
      return 'Enter a new code'
    case 'change_service':
      return 'Change service'
    case 'start_again':
      return 'Start again'
    case 'new_invitation':
      return reading === 'camera'
        ? 'Scan again'
        : reading === 'photo'
          ? 'Choose another photo'
          : 'Paste again'
    case 'open_settings':
      return 'Open Settings'
    case 'done':
      return 'Done'
  }
}

/** The characters a code is made of: base58, which leaves out 0, O, I and l. */
const CODE_ALPHABET = /^[1-9A-HJ-NP-Za-km-z]$/

/**
 * What is wrong with a typed code, or null when it is ten characters of the alphabet. Spaces and
 * hyphens are separators and are ignored; nothing else is.
 */
export function codeProblem(typed: string): string | null {
  const characters = [...typed].filter((character) => character !== ' ' && character !== '-')
  const wrong = characters.find((character) => !CODE_ALPHABET.test(character))
  if (wrong !== undefined) {
    return `A code never contains “${wrong}”. It uses no 0, O, I or l.`
  }
  if (characters.length > 10) return 'A code has ten characters.'
  return null
}

/** True when a typed code is ten characters of the alphabet. */
export function codeComplete(typed: string): boolean {
  const characters = [...typed].filter((character) => character !== ' ' && character !== '-')
  return characters.length === 10 && codeProblem(typed) === null
}

/** A clock time a person reads, like 14:30. */
export function clockTime(ms: number): string {
  return new Date(ms).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
}

/** How long is left until `ms`, in whole minutes, never less than zero. */
export function minutesLeft(ms: number, now: number): number {
  return Math.max(0, Math.ceil((ms - now) / 60_000))
}

/** "4 minutes left", "1 minute left", or "Less than a minute left". */
export function timeLeft(ms: number, now: number): string {
  const minutes = minutesLeft(ms, now)
  if (ms - now <= 60_000) return 'less than a minute left'
  return minutes === 1 ? '1 minute left' : `${minutes} minutes left`
}

/** "1:52 left", for a confirmation's own short lifetime. */
export function secondsLeft(ms: number, now: number): string {
  const seconds = Math.max(0, Math.floor((ms - now) / 1000))
  const minutes = Math.floor(seconds / 60)
  return `${minutes}:${String(seconds % 60).padStart(2, '0')} left`
}

/** A grouped verification value spelled for a screen reader: "f 3 c 1, 4 6 f d". */
export function spelledValue(value: string): string {
  return value
    .split(' ')
    .map((group) => [...group].join(' '))
    .join(', ')
}
