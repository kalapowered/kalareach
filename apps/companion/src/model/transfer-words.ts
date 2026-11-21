/**
 * What a person is told about a file sent to a host this device is paired with.
 *
 * The first group is the application's own words, written in `open_transfers.rs` and
 * `paired_drafts.rs`: the page shows them as written and recognises a refusal by them, so a case
 * reads those two files and holds the constants here to them. The second group is the page's own
 * words for what the host refused and for each state of an upload.
 */

import { failureCode, failureWords, isHostError } from '../host/port'

/** A cancel names no upload this device holds. */
export const NO_OPEN_UPLOAD = 'no open upload has that key'

/** A third open upload is refused. */
export const TOO_MANY_OPEN =
  'two files are open on this host already: wait for one to finish, or cancel one'

/** An upload kept from before whose content is gone or changed. */
export const CANNOT_RESUME =
  'this file cannot be resumed from where it stopped, because the copy this device kept is gone or has changed: cancel it and send the file again'

/** An upload whose reservation was asked for and whose answer never came. */
export const UNRECOVERABLE =
  'this device asked the host to take this file and did not get its answer: if the host agreed, it keeps the place for up to 24 hours and then releases it'

/** A transfer key that an open upload, an entry or a copy holds already. */
export const KEY_IN_USE = 'an upload with that transfer key is open already'

/** What the command that waited for an upload is told when the person cancelled it. */
export const CANCELLED_BEFORE_SENT = 'this file was cancelled before it was sent in full'

/** A cancel of an upload that is already published. */
export const PUBLISHED_AND_KEPT =
  'this file was already sent in full and the host keeps it: it was not cancelled'

/** The session or the draft a file was for is gone on the host. */
export const DRAFT_GONE =
  'the session or the draft this file was for is gone on the host: the file was not added to it'

/** The session or the draft a message was for is gone on the host. */
export const DRAFT_GONE_FOR_TEXT =
  'the session or the draft this message was for is gone on the host: the message was not sent'

/** This device keeps no draft for the session a text was for. */
export const NO_DRAFT = 'this device keeps no draft for this session: add a file to it first'

/** The draft this device kept for the session is of a later release. */
export const NEWER_DRAFT =
  'this device keeps a draft for this session in a format this release does not read: update the application to use it'

/** The draft changed twice while a file was being added to it. */
export const CHANGED_AGAIN = 'the draft changed again while the file was being added: the file was not added'

/** The host was asked to make the draft and its answer has not been received. */
export const CREATE_PENDING =
  'the host was asked to make a draft for this session and its answer has not been received: try again later'

/** The host was asked to end the draft and its answer has not been received. */
export const DISCARD_PENDING =
  'the host was asked to end the draft for this session and its answer has not been received: try again later'

/** A host of an earlier build cannot end a draft. */
export const UPDATE_THE_HOST_TO_END_A_DRAFT =
  'update the host: it cannot end a draft this device no longer needs'

/** A host that is an earlier build refused a method a file needs. */
export const EARLIER_HOST =
  'This host is an earlier version and cannot take files from this device: update the host.'

/** The host's own refusal of an upload for want of a right. */
export const NO_RIGHT_TO_SEND =
  "This device may not send files to this host: ask the host's owner to allow it."

/** The host has no room for the file now. No totals are said. */
export const NO_ROOM =
  'The host has no room for this file now: wait for other files to finish, or try again later.'

/** The file changed while it was being sent. */
export const FILE_CHANGED = 'This file changed while it was being sent: choose it again to send it.'

/** The sentence a person reads: the application's words with their first letter capital, and no other change. */
export function sentence(words: string): string {
  const first = words.charAt(0)
  return first.toUpperCase() + words.slice(1)
}

/** What kind of refusal an upload or a bind met. */
export type RefusalKind =
  | 'cancelled'
  | 'too-many'
  | 'gone'
  | 'earlier-host'
  | 'no-right'
  | 'no-room'
  | 'file-changed'
  | 'other'

/** A refusal, with the words a person reads for it. */
export interface Refusal {
  readonly kind: RefusalKind
  readonly words: string
}

const APPLICATION_WORDS: readonly (readonly [string, RefusalKind])[] = [
  [CANCELLED_BEFORE_SENT, 'cancelled'],
  [TOO_MANY_OPEN, 'too-many'],
  [DRAFT_GONE, 'gone'],
  [DRAFT_GONE_FOR_TEXT, 'gone'],
  [NO_DRAFT, 'gone'],
  // The application refuses these as it refuses a missing right, so its code cannot tell them apart:
  // each is shown in its own words and not as a right the device lacks.
  [CANNOT_RESUME, 'other'],
  [KEY_IN_USE, 'other'],
  [NEWER_DRAFT, 'other'],
  [CHANGED_AGAIN, 'other'],
  [CREATE_PENDING, 'other'],
  [DISCARD_PENDING, 'other'],
  [UPDATE_THE_HOST_TO_END_A_DRAFT, 'other']
]

/**
 * What a refusal of an upload, a bind or a text means to the person, and the words to show.
 *
 * The application's own sentences are recognised by their words and shown as written. A host's
 * refusal is recognised by its protocol code: an earlier build says it does not know the method, a
 * full staging area says its quota, a changed file says its source changed, and a right the device
 * lacks is a permission refusal. Anything else is shown in the host's own words.
 */
/** Whether `failure` says the application holds no upload under the key: nothing was cancelled. */
export function isNoOpenUpload(failure: unknown): boolean {
  return failureWords(failure) === NO_OPEN_UPLOAD
}

export function refusalOf(failure: unknown): Refusal {
  const words = failureWords(failure)
  for (const [known, kind] of APPLICATION_WORDS) {
    if (words === known) return { kind, words: sentence(known) }
  }
  const code = isHostError(failure) ? failureCode(failure) : null
  switch (code) {
    case 'UNSUPPORTED_CAPABILITY':
    case 'UNSUPPORTED_SCHEMA':
      return { kind: 'earlier-host', words: EARLIER_HOST }
    case 'QUOTA_EXCEEDED':
    case 'STORAGE_UNAVAILABLE':
      return { kind: 'no-room', words: NO_ROOM }
    case 'ATTACHMENT_INTEGRITY':
    case 'SOURCE_CHANGED':
      return { kind: 'file-changed', words: FILE_CHANGED }
    case 'PERMISSION_DENIED':
      return { kind: 'no-right', words: NO_RIGHT_TO_SEND }
    default:
      return { kind: 'other', words: sentence(words) }
  }
}

/** Said once when the sign-in changed and the files this window held for the earlier one were taken off the screen. */
export const FILES_OF_EARLIER_SIGN_IN_REMOVED = 'Files added under the earlier sign-in were removed from this screen.'
