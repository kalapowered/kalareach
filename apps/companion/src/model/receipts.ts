/**
 * Queued, sent, applied: what the person's own input is doing.
 *
 * Section 13 asks for these three as different states, and section 9 says where they come from. The
 * first is local: the text is in the composer and nothing has left this device. The second is a
 * request that is with the host. The third needs a receipt, and only a receipt: a network
 * acknowledgement says the bytes arrived, not that the agent took the prompt.
 *
 * The reconnect banner rests on the same rule. It reports what is unresolved; it never reports
 * success because a connection came back.
 */

import type { Receipt } from '@kalareach/protocol'

/** What has happened to one thing the person sent. */
export type InputState = 'queued' | 'sent' | 'applied' | 'refused' | 'rejected' | 'unknown'

/** One submission the interface is tracking. */
export interface Submission {
  /** This device's own identity for the submission, which exists before an action does. */
  readonly localId: string
  /** The action identifier, once the request has been made. */
  readonly actionId: string | null
  /** The text or label the person will recognise. */
  readonly label: string
  /**
   * Exactly what was submitted.
   *
   * Kept until the outcome permits letting it go, because a refusal has to be able to give it
   * back, and the label above is a trimmed thing to show rather than the text itself.
   */
  readonly text: string
  /** Its current state. */
  readonly state: InputState
  /** The revision of the newest receipt this has taken, so that an older one never replaces it. */
  readonly revision?: string
  /**
   * The stored draft the prompt was sent from, when the device kept one for it. A phone keeps its
   * unresolved submissions across a restart, and this is how a prompt that is then said to have been
   * applied finds the draft that holds its text: the draft, and not any draft with the same words.
   */
  readonly storedDraftId?: string
  /** When it was created. */
  readonly createdAtMs: number
  /** The failure, when it has one. */
  readonly error: { readonly code: string; readonly message: string } | null
}

/**
 * The state a receipt puts a submission in.
 *
 * `received`, `accepted` and `dispatching` are all "with the host and not done". `applied` is the
 * only one that means the effect happened. The rest are outcomes of their own, and `unknown` is
 * the one the interface must never round up: it is the state whose whole point is that nobody
 * knows.
 */
export function stateOfReceipt(receipt: Receipt): InputState {
  switch (receipt.state) {
    case 'received':
    case 'accepted':
    case 'dispatching':
      return 'sent'
    case 'applied':
      return 'applied'
    case 'refused':
      return 'refused'
    case 'rejected':
      return 'rejected'
    case 'unknown':
      return 'unknown'
    default:
      return 'unknown'
  }
}

/** What the interface says about a state. */
export function describeState(state: InputState): string {
  switch (state) {
    case 'queued':
      return 'Queued on this device'
    case 'sent':
      return 'Sent, waiting for the host'
    case 'applied':
      return 'Applied'
    case 'refused':
      return 'Refused by the host'
    case 'rejected':
      return 'Rejected'
    case 'unknown':
      return 'Outcome unknown'
  }
}

/** A submission that has not left this device. */
export function queued(
  localId: string,
  label: string,
  createdAtMs: number,
  text = label
): Submission {
  return { localId, actionId: null, label, text, state: 'queued', createdAtMs, error: null }
}

/** Whether an outcome means the submission did not happen and its text should come back. */
export function wasRefused(state: InputState): boolean {
  return state === 'refused' || state === 'rejected'
}

/** Records that the request has been made. */
export function sent(submission: Submission, actionId: string): Submission {
  return { ...submission, actionId, state: 'sent' }
}

/**
 * Records what a receipt said.
 *
 * The revision held is the newest one seen: an event can report where an action stands without
 * saying which revision of the record that is, and it must not make the submission forget the
 * revision it has, which is what puts an older record in its place.
 */
export function settled(submission: Submission, receipt: Receipt): Submission {
  return {
    ...submission,
    actionId: receipt.action_id,
    state: stateOfReceipt(receipt),
    error: receipt.error
      ? { code: String(receipt.error.code), message: String(receipt.error.message) }
      : null,
    revision: receipt.revision ?? submission.revision
  }
}

/**
 * What a settled submission means for the prompt it carried: whether the host took it, did not,
 * or nobody knows. Null while the host still has it, because a prompt the host has only accepted is
 * not yet a prompt it took.
 */
export function sendOutcomeOf(state: InputState): 'taken' | 'refused' | 'unknown' | null {
  switch (state) {
    case 'applied':
      return 'taken'
    case 'refused':
    case 'rejected':
      return 'refused'
    case 'unknown':
      return 'unknown'
    case 'queued':
    case 'sent':
      return null
  }
}

/**
 * Why nothing more is sent while an outcome is unknown, or null when none is.
 *
 * An action whose outcome nobody knows may have been dispatched, and the person's text comes back to
 * the composer: sending it again could run it twice. A later receipt settles it, or the host's
 * record of it when the interface asks, or a person who has checked sends it anyway, as an action of
 * its own that leaves this one listed as it is.
 */
export function unconfirmedReason(submissions: readonly Submission[]): string | null {
  const count = submissions.filter((submission) => submission.state === 'unknown').length
  return count === 0 ? null : unconfirmedWords(count)
}

/** The sentence for `count` actions that have no confirmed outcome. */
export function unconfirmedWords(count: number): string {
  return `${count === 1 ? 'One action has' : `${String(count)} actions have`} no confirmed outcome yet. ${count === 1 ? 'It' : 'They'} may still run, so sending again could make the work happen twice.`
}

/** What the way past that hold is called: the person has looked, and takes the risk. */
export const SEND_ANYWAY_WORDS = 'I checked; send anyway'

/** Whether the host will not change what it said of an action: applied, refused or rejected. */
function isFinal(state: InputState): boolean {
  return state === 'applied' || state === 'refused' || state === 'rejected'
}

/** Whether `revision` is a receipt revision older than `held`; a revision that is not one is never older. */
function isOlder(revision: string | undefined, held: string | undefined): boolean {
  if (revision === undefined || held === undefined) return false
  try {
    return BigInt(revision) < BigInt(held)
  } catch {
    return false
  }
}

/**
 * What a receipt that arrives later does to a submission: by an event, or because the host's record
 * of the action was read.
 *
 * It never goes back. A final state is terminal; a receipt older than the one already taken says
 * less than it, and an answer read before an event may arrive after it; and an outcome nobody knows
 * stays unknown until the host says it was applied or refused, so that a record that still reads
 * `accepted` does not lift the hold on sending it again.
 */
export function applyReceipt(submission: Submission, receipt: Receipt): Submission {
  if (isFinal(submission.state)) return submission
  if (isOlder(receipt.revision, submission.revision)) return submission
  const next = settled(submission, receipt)
  if (submission.state === 'unknown' && !isFinal(next.state)) return submission
  // A record that says what the submission already says is not news: the same submission comes
  // back, so that reading the host's record again changes nothing.
  return next.state === submission.state &&
    next.revision === submission.revision &&
    next.actionId === submission.actionId &&
    next.error?.code === submission.error?.code &&
    next.error?.message === submission.error?.message
    ? submission
    : next
}

/** Records a failure the request itself produced. */
export function failed(
  submission: Submission,
  error: { code: string; message: string }
): Submission {
  // A submission whose outcome the host could not confirm stays unknown: the interface asks what
  // became of it rather than telling the person it failed.
  const state: InputState = error.code === 'OUTCOME_UNKNOWN' ? 'unknown' : 'refused'
  return { ...submission, state, error }
}

/** The submissions that are not finished, which is what the reconnect banner lists. */
export function unresolved(submissions: readonly Submission[]): readonly Submission[] {
  return submissions.filter(
    (submission) =>
      submission.state === 'queued' || submission.state === 'sent' || submission.state === 'unknown'
  )
}

/**
 * What the reconnect banner says.
 *
 * It never says an action succeeded. While anything is unresolved it says so and counts them; when
 * nothing is, it says the connection is back and nothing more. Before anything has answered
 * whether the host is in contact, `connected` is null and it says nothing at all: neither contact
 * nor its loss is known yet.
 */
export function reconnectBanner(
  connected: boolean | null,
  submissions: readonly Submission[]
): { readonly tone: 'warning' | 'accent'; readonly title: string; readonly detail: string } | null {
  if (connected === null) return null
  const pending = unresolved(submissions)
  if (!connected) {
    return {
      tone: 'warning',
      title: 'Not in contact with this host',
      detail:
        pending.length > 0
          ? `${pending.length} ${pending.length === 1 ? 'action has' : 'actions have'} no confirmed outcome. Their processes may still be running.`
          : 'Its processes may still be running. Nothing here says they are not.'
    }
  }
  if (pending.length > 0) {
    return {
      tone: 'accent',
      title: 'Connected again',
      detail: `${pending.length} ${pending.length === 1 ? 'action is' : 'actions are'} still waiting for a receipt. The connection coming back is not an outcome.`
    }
  }
  return null
}

/**
 * What a mutation's answer carries: the receipt, the method's own result, or only the action's
 * identity when the host never confirmed what became of it.
 */
export interface Answer {
  readonly receipt: Receipt | null
  readonly value: unknown
  readonly action_id: string | null
}

/**
 * The state one answer puts a submission in.
 *
 * A receipt says it in its own state. A host answers with the method's own result only for an
 * action it performed, so a result is applied. An answer that carries neither is an action whose
 * outcome nobody knows, which is never rounded up to a success or down to a refusal.
 */
export function answeredState(answer: Answer): InputState {
  if (answer.receipt !== null) return stateOfReceipt(answer.receipt)
  if (answer.value !== null && answer.value !== undefined) return 'applied'
  return 'unknown'
}

/**
 * What one answer means, in words.
 *
 * Only an applied action is completion. Everything else is named for what it is, because "waiting"
 * for an outcome the host has already refused is the one thing the receipt contract exists to
 * prevent.
 */
export function outcomeMessage(done: string, answer: Answer): string {
  switch (answeredState(answer)) {
    case 'applied':
      return `${done}.`
    case 'refused':
      return 'The host refused that.'
    case 'rejected':
      return 'The host rejected that.'
    case 'unknown':
      return 'The host could not confirm what became of that.'
    case 'queued':
    case 'sent':
      return 'Sent. Waiting for the host to confirm.'
  }
}

/**
 * How an answer reads. Only an applied action is completion; anything still with the host is
 * pending, and a pending outcome wearing a completion mark is the same false claim in another
 * shape.
 */
export function outcomeTone(answer: Answer): 'success' | 'danger' | 'pending' {
  switch (answeredState(answer)) {
    case 'applied':
      return 'success'
    case 'queued':
    case 'sent':
      return 'pending'
    case 'refused':
    case 'rejected':
    case 'unknown':
      return 'danger'
  }
}

/**
 * Records what one answer said about a submission: its receipt's state, applied for a host's own
 * result, and unknown for an answer that carried only the action's identity.
 */
export function answered(submission: Submission, answer: Answer): Submission {
  if (answer.receipt !== null) return settled(submission, answer.receipt)
  const identified =
    answer.action_id === null ? submission : { ...submission, actionId: answer.action_id }
  return { ...identified, state: answeredState(answer), error: null }
}
