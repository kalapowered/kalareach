/**
 * Deleting the account, as the page is told about it and in the words it says it.
 *
 * The page asks the backend what deleting would do, asks for the emailed code, confirms with it,
 * and learns how the removal goes. It names the code and the organisations the person accepted
 * losing and nothing else: the token, the address the code goes to and the receipt that settles a
 * lost answer stay in the backend. Every answer is a value the page branches on; a step that could
 * not be taken is a `DeletionProblem`, a kind and never a message, so what a person reads is
 * here.
 *
 * The words follow the same rule as the rest of the account panel: nothing to buy. A paid feature
 * set up on the website is called that, never by the words in `PURCHASE_WORDS`, and the policy is
 * named as text and never linked.
 */

import { ACCOUNT_HOST } from './account'

/** Something the person should know before they confirm. */
export type DeletionWarning =
  | {
      readonly kind: 'organisation_owner'
      readonly organisation_id: string
      readonly name: string
      readonly members: number
    }
  | { readonly kind: 'subscription' }
  | { readonly kind: 'credit' }
  | { readonly kind: 'money_owed' }

/** What a deletion removes. */
export type DeletedKind =
  | 'sign_ins'
  | 'passkeys_and_address'
  | 'backup_records'
  | 'recovery_bundle'
  | 'relay_and_voice_ended'
  | 'payment_record'
  | 'organisation_memberships'
  | 'device_registrations'

/** What a deletion leaves. */
export type KeptKind =
  | 'billing_records'
  | 'relay_records'
  | 'call_records'
  | 'reasoning_records'
  | 'backup_index_rows'
  | 'organisation_records'
  | 'device_records'
  | 'recovery_copies'
  | 'other_services'

/** What deleting the account would do, as the service says it. */
export interface DeletionPreview {
  /** The account's address, masked by the service. */
  readonly address: string
  readonly warnings: readonly DeletionWarning[]
  readonly deleted: readonly DeletedKind[]
  readonly kept: readonly KeptKind[]
  /** Whether the service listed something removed or kept that this version has no words for. */
  readonly unlisted: boolean
  /** Years the invoices and records of what was charged are kept. */
  readonly kept_records_years: number
  /** Days within which stored backup files are removed. */
  readonly backup_file_days: number
  /** Minutes the code lasts. */
  readonly code_lifetime_minutes: number
}

/** An organisation the account owns. */
export interface OwnedOrganisation {
  readonly organisation_id: string
  readonly name: string
  readonly members: number
}

/** Why a step could not be taken. */
export type DeletionProblem =
  | { readonly kind: 'needs_sign_in' }
  | { readonly kind: 'refused' }
  | { readonly kind: 'busy'; readonly seconds: number }
  | { readonly kind: 'mail_failed' }
  | { readonly kind: 'unsure' }
  | { readonly kind: 'unreachable' }
  | { readonly kind: 'account_changed' }

/** Why a code was refused. */
export type CodeRefusal = 'wrong' | 'expired' | 'spent'

/** What reading what deleting would do came to. */
export type DeletionViewAnswer =
  | { readonly state: 'ready'; readonly preview: DeletionPreview }
  | { readonly state: 'cannot_show' }
  | { readonly state: 'problem'; readonly problem: DeletionProblem }

/** What asking for the code came to. */
export type DeletionSendAnswer =
  | { readonly state: 'sent' }
  | { readonly state: 'problem'; readonly problem: DeletionProblem }

/** What the confirmation came to. */
export type DeletionConfirmAnswer =
  | { readonly state: 'closed'; readonly finished: boolean }
  | {
      readonly state: 'code_refused'
      readonly reason: CodeRefusal
      readonly attempts_left: number
    }
  | { readonly state: 'acknowledge'; readonly organisations: readonly OwnedOrganisation[] }
  | { readonly state: 'unsettled' }
  | { readonly state: 'problem'; readonly problem: DeletionProblem }

/**
 * How the removal is going. `unsettled` is a confirmation that left and has no answer yet, here or
 * at the service: it may still close the account.
 */
export type DeletionStatusAnswer =
  | { readonly state: 'none' | 'unsettled' | 'open' | 'done' }
  | { readonly state: 'problem'; readonly problem: DeletionProblem }

/** How many digits the code has. */
export const CODE_DIGITS = 8

/** How often the result asks how the removal goes, and for how long. */
export const STATUS_EVERY_MS = 3000
export const STATUS_FOR_MS = 2 * 60 * 1000

/** The note beside the button that opens the step. */
export const ENTRY_NOTE =
  'Removes the account and every sign-in. Your hosts, sessions and settings on this device stay.'

/** What stays on this device, said before the person goes on. */
export const DEVICE_LINE = 'Your hosts, sessions and settings stay on this device.'

/** Where the full list and the periods are, named as text. */
export const POLICY_LINE = `The privacy policy at ${ACCOUNT_HOST}/privacy has the full list and the periods.`

/** Where an account is deleted when this version cannot do it. */
export const WEB_ADDRESS = `${ACCOUNT_HOST}/account/delete`

/** What the service does about money, said whether or not a warning came with it. */
export const MONEY_LINES: readonly string[] = [
  'Paid features you set up on the website end at once.',
  'There is no refund, and time you have not used is lost.',
  'Any credit you hold is lost.'
]

/** The line a warning adds. */
export function describeWarning(warning: DeletionWarning): string {
  switch (warning.kind) {
    case 'organisation_owner':
      return `You own the organisation ${warning.name}, with ${String(warning.members)} members. It will have no owner, and no one will be able to run it.`
    case 'subscription':
      return 'You have paid features set up now. They end at once.'
    case 'credit':
      return 'You hold a credit balance. It is lost.'
    case 'money_owed':
      return 'You owe money. It stays recorded, and deleting does not clear it.'
  }
}

/** One thing a deletion removes, in words. */
export function describeDeleted(kind: DeletedKind, preview: DeletionPreview): string {
  switch (kind) {
    case 'sign_ins':
      return 'Every sign-in on every device ends now.'
    case 'passkeys_and_address':
      return 'Your passkeys, address and name are deleted.'
    case 'backup_records':
      return `Your backup records are deleted. The backup files are removed within ${String(preview.backup_file_days)} days.`
    case 'recovery_bundle':
      return 'Your recovery bundle is deleted. A recovery kit can no longer restore from it.'
    case 'relay_and_voice_ended':
      return 'Your relay and voice use ends.'
    case 'payment_record':
      return 'Your customer record at Stripe is deleted.'
    case 'organisation_memberships':
      return 'Your organisation memberships end. Hosts your organisation manages need an account to connect.'
    case 'device_registrations':
      return "The notification registrations and settings copies of the devices your account's records name are deleted. Notifications on them may stop until they register again."
  }
}

/**
 * One thing a deletion leaves, in words. Everything the service keeps for the account is deleted
 * after the same number of years, which the preview carries; what belongs to an organisation stays
 * with the organisation.
 */
export function describeKept(kind: KeptKind, preview: DeletionPreview): string {
  const years = String(preview.kept_records_years)
  switch (kind) {
    case 'billing_records':
      return `Invoices and records of what was charged stay for ${years} years, under an identifier with no name or address, and are then deleted.`
    case 'relay_records':
      return `Records of relay leases and use stay for ${years} years, and are then deleted.`
    case 'call_records':
      return `Records of voice calls stay for ${years} years, and are then deleted.`
    case 'reasoning_records':
      return `Records of voice reasoning requests stay for ${years} years, and are then deleted.`
    case 'backup_index_rows':
      return `An index row for each backed-up object stays for ${years} years, and is then deleted.`
    case 'organisation_records':
      return 'Records that belong to an organisation stay with the organisation.'
    case 'device_records':
      return `Records that name your devices' keys stay for ${years} years, and are then deleted.`
    case 'recovery_copies':
      return 'Our own recovery copies of the service hold deleted data for a short time. The privacy policy gives the period.'
    case 'other_services':
      return 'Services we use keep their own records under their own terms.'
  }
}

/** The line shown when the service listed more than this version can word. */
export const UNLISTED_LINE = `More is deleted or kept than this version of KalaReach can list. The privacy policy at ${ACCOUNT_HOST}/privacy has the full list.`

/** The line shown when a warning or a choice is not one this version knows. */
export const CANNOT_SHOW_LINE = `KalaReach cannot show what this deletion does with money or organisations. Update KalaReach, or delete the account at ${WEB_ADDRESS}.`

/** How long to wait, in words. */
function describeWait(seconds: number): string {
  if (seconds < 60) return `${String(Math.max(1, Math.ceil(seconds)))} seconds`
  const minutes = Math.ceil(seconds / 60)
  return minutes === 1 ? 'about a minute' : `about ${String(minutes)} minutes`
}

/**
 * Where a step is, which decides what a failure to reach the service claims: before anything was
 * sent nothing changed; once a confirmation has left without an answer, whether it went through is
 * not known; once the account is closed, the deletion goes on without this device.
 */
export type Stage = 'before' | 'unknown' | 'after'

/** What not reaching the service means, by where the step is. */
function describeUnreachable(stage: Stage): string {
  if (stage === 'before') {
    return `KalaReach could not reach ${ACCOUNT_HOST}. Nothing changed. Try again.`
  }
  if (stage === 'unknown') {
    return `KalaReach could not reach ${ACCOUNT_HOST} just now. Try again in a moment.`
  }
  return 'KalaReach could not check just now. The deletion goes on without it, and KalaReach checks again.'
}

/** A step that could not be taken, in words. */
export function describeProblem(problem: DeletionProblem, stage: Stage = 'before'): string {
  switch (problem.kind) {
    case 'needs_sign_in':
      return 'Your sign-in on this device has ended. Sign in again, then delete the account.'
    case 'refused':
      return `This version of KalaReach and the service do not agree on this request. Update KalaReach, or delete the account at ${WEB_ADDRESS}.`
    case 'busy':
      return `Too many tries. Try again in ${describeWait(problem.seconds)}.`
    case 'mail_failed':
      return 'The email could not be sent. Try again.'
    case 'unsure':
      return 'We could not tell whether the email was sent. Check your email, or send another code.'
    case 'unreachable':
      return describeUnreachable(stage)
    case 'account_changed':
      return 'A different account is signed in now. Start again.'
  }
}

/** A code the service refused, in words. */
export function describeRefusal(reason: CodeRefusal, attemptsLeft: number): string {
  switch (reason) {
    case 'wrong':
      return attemptsLeft > 0
        ? `That code is not right. You have ${String(attemptsLeft)} tries left on it.`
        : 'Too many wrong tries. Send a new code.'
    case 'expired':
      return 'That code has expired. Send a new one.'
    case 'spent':
      return "That code can't be used any more. Send a new one."
  }
}

/** The line that says the code was sent, or may have been. */
export function describeCodeSent(preview: DeletionPreview, sure: boolean): string {
  const digits = String(CODE_DIGITS)
  const minutes = String(preview.code_lifetime_minutes)
  return sure
    ? `We sent an ${digits}-digit code to ${preview.address}. It works for ${minutes} minutes.`
    : `An ${digits}-digit code may have been sent to ${preview.address}. It works for ${minutes} minutes.`
}

/** The line that says the account owns more organisations than one request can accept. */
export const TOO_MANY_ORGANISATIONS_LINE = `This account owns more organisations than the app can accept at once. Delete the account at ${WEB_ADDRESS}.`

/** The most organisations one confirmation can accept. */
export const ACKNOWLEDGED_MAXIMUM = 50

/** The code field's contents: digits only, at most as many as the code has. */
export function digitsOf(text: string): string {
  return text.replace(/\D/g, '').slice(0, CODE_DIGITS)
}

/** The result, in words. */
export const RESULT_CLOSED = 'Your account is closed. Nothing can sign in to it now.'
export const RESULT_FINISHING =
  'We are finishing the removal. This usually takes minutes, and longer if a provider is down.'

/** When the backup files go, said once the person has read it before. */
export function describeBackupFiles(days: number): string {
  return `Backup files are removed within ${String(days)} days.`
}
export const RESULT_STILL = 'Still finishing. KalaReach checks again the next time you open Account.'
export const RESULT_DONE = 'Your account is deleted.'
export const RESULT_NO_EMAIL = 'You will not get an email.'
export const UNSETTLED_LINE = 'We could not tell whether the deletion went through.'
export const STILL_UNKNOWN_LINE = 'It is still not known whether the deletion went through.'
export const NOT_DONE_LINE = 'The deletion did not go through. Your account is still open.'
export const ACKNOWLEDGE_LINE = 'These organisations will lose their owner.'
